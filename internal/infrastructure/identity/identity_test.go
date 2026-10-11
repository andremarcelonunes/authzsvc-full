package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// backend plays the backend's translation endpoint.
type backend struct {
	srv    *httptest.Server
	hits   atomic.Int32
	key    atomic.Value // last X-API-Key
	path   atomic.Value
	status int
	body   string
	delay  time.Duration
}

func newBackend(t *testing.T, status int, body string) *backend {
	t.Helper()
	b := &backend{status: status, body: body}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		b.key.Store(r.Header.Get("X-API-Key"))
		b.path.Store(r.URL.Path)
		if b.delay > 0 {
			time.Sleep(b.delay)
		}
		w.WriteHeader(b.status)
		w.Write([]byte(b.body))
	}))
	t.Cleanup(b.srv.Close)
	return b
}

const okBody = `{"authz_user_id":4774,"backend_user_id":58,"latency_ms":77.3}`

func TestHTTPResolver_Found(t *testing.T) {
	b := newBackend(t, 200, okBody)
	r := NewHTTPResolver(b.srv.URL+"/", "secret-key", time.Second)
	id, found, err := r.ResolveBackendUserID(context.Background(), 4774)
	if err != nil || !found || id != "58" {
		t.Fatalf("got %q %v %v", id, found, err)
	}
	if got := b.key.Load(); got != "secret-key" {
		t.Errorf("X-API-Key = %v", got)
	}
	if got := b.path.Load(); got != "/api/v1/internal/users/authz/4774/backend" {
		t.Errorf("path = %v", got)
	}
}

func TestHTTPResolver_NotFound(t *testing.T) {
	b := newBackend(t, 404, `{"detail":"No backend user found for AuthzSvc ID 999999"}`)
	id, found, err := NewHTTPResolver(b.srv.URL, "k", time.Second).ResolveBackendUserID(context.Background(), 999999)
	if err != nil || found || id != "" {
		t.Fatalf("got %q %v %v", id, found, err)
	}
}

func TestHTTPResolver_Errors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"500", 500, "oops"},
		{"401", 401, "{}"},
		{"bad JSON", 200, "not json"},
		{"missing id", 200, `{"authz_user_id":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBackend(t, tc.status, tc.body)
			_, found, err := NewHTTPResolver(b.srv.URL, "secret-key", time.Second).ResolveBackendUserID(context.Background(), 1)
			if err == nil || found {
				t.Fatalf("expected error, got found=%v err=%v", found, err)
			}
			if strings.Contains(err.Error(), "secret-key") {
				t.Errorf("error leaks the API key: %v", err)
			}
		})
	}
}

func TestHTTPResolver_Timeout(t *testing.T) {
	b := newBackend(t, 200, okBody)
	b.delay = 300 * time.Millisecond
	start := time.Now()
	_, _, err := NewHTTPResolver(b.srv.URL, "k", 50*time.Millisecond).ResolveBackendUserID(context.Background(), 1)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("timeout not honoured: %v", time.Since(start))
	}
}

func TestHTTPResolver_NetworkFailureAndDefaultTimeout(t *testing.T) {
	b := newBackend(t, 200, okBody)
	url := b.srv.URL
	b.srv.Close()
	r := NewHTTPResolver(url, "k", 0)
	if r.client.Timeout != DefaultTimeout {
		t.Errorf("default timeout = %v", r.client.Timeout)
	}
	if _, found, err := r.ResolveBackendUserID(context.Background(), 1); err == nil || found {
		t.Errorf("expected network error, found=%v err=%v", found, err)
	}
}

func newCached(t *testing.T, b *backend) (*CachedResolver, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewCachedResolver(NewHTTPResolver(b.srv.URL, "k", time.Second), rdb), mr
}

func TestCachedResolver_PositiveCached(t *testing.T) {
	b := newBackend(t, 200, okBody)
	c, mr := newCached(t, b)
	for i := 0; i < 3; i++ {
		id, found, err := c.ResolveBackendUserID(context.Background(), 4774)
		if err != nil || !found || id != "58" {
			t.Fatalf("got %q %v %v", id, found, err)
		}
	}
	if b.hits.Load() != 1 {
		t.Errorf("backend hit %d times", b.hits.Load())
	}
	if ttl := mr.TTL(KeyPrefix + "4774"); ttl != PositiveTTL {
		t.Errorf("ttl = %v", ttl)
	}
}

func TestCachedResolver_NegativeCached(t *testing.T) {
	b := newBackend(t, 404, `{}`)
	c, mr := newCached(t, b)
	for i := 0; i < 3; i++ {
		if id, found, err := c.ResolveBackendUserID(context.Background(), 7); err != nil || found || id != "" {
			t.Fatalf("got %q %v %v", id, found, err)
		}
	}
	if b.hits.Load() != 1 {
		t.Errorf("backend hit %d times", b.hits.Load())
	}
	if ttl := mr.TTL(KeyPrefix + "7"); ttl != NegativeTTL {
		t.Errorf("ttl = %v", ttl)
	}
	mr.FastForward(NegativeTTL + time.Second)
	c.ResolveBackendUserID(context.Background(), 7)
	if b.hits.Load() != 2 {
		t.Errorf("expired entry not refreshed: %d hits", b.hits.Load())
	}
}

func TestCachedResolver_ErrorsNotCached(t *testing.T) {
	b := newBackend(t, 500, "x")
	c, mr := newCached(t, b)
	for i := 0; i < 2; i++ {
		if _, _, err := c.ResolveBackendUserID(context.Background(), 5); err == nil {
			t.Fatal("expected error")
		}
	}
	if b.hits.Load() != 2 {
		t.Errorf("backend hit %d times", b.hits.Load())
	}
	if mr.Exists(KeyPrefix + "5") {
		t.Error("error was cached")
	}
}

func TestCachedResolver_CacheFailureFallsThrough(t *testing.T) {
	b := newBackend(t, 200, okBody)
	c, mr := newCached(t, b)
	mr.Close() // Redis is gone: reads and writes fail
	id, found, err := c.ResolveBackendUserID(context.Background(), 4774)
	if err != nil || !found || id != "58" {
		t.Fatalf("got %q %v %v", id, found, err)
	}
	if b.hits.Load() != 1 {
		t.Errorf("backend hit %d times", b.hits.Load())
	}
}

func TestCachedResolver_CorruptEntryRefreshed(t *testing.T) {
	b := newBackend(t, 200, okBody)
	c, mr := newCached(t, b)
	mr.Set(KeyPrefix+"4774", "garbage")
	if id, found, err := c.ResolveBackendUserID(context.Background(), 4774); err != nil || !found || id != "58" {
		t.Fatalf("got %q %v %v", id, found, err)
	}
}
