// Package smsbudget implements domain.SMSBudget on Redis.
package smsbudget

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

const (
	phoneDayWindow   = 24 * time.Hour
	phoneMonthWindow = 30 * 24 * time.Hour
	ipDayWindow      = 24 * time.Hour
	globalDayTTL     = 48 * time.Hour
	globalMonthTTL   = 40 * 24 * time.Hour
	sentDayTTL       = 40 * 24 * time.Hour
	sentMonthTTL     = 400 * 24 * time.Hour
)

// reserveScript checks every limit and, only if all pass, consumes one unit of each, atomically.
// KEYS: 1 global day, 2 global month, 3 phone interval, 4 phone day, 5 phone 30 days, 6 ip day.
// ARGV: 1 daily cap, 2 monthly cap, 3 interval ms, 4 phone/day cap, 5 phone/30d cap, 6 ip cap,
//       7 global day ttl ms, 8 global month ttl ms, 9 phone day ms, 10 phone 30d ms, 11 ip day ms.
// Returns {code, retry_ms}: 0 reserved, 1 global month, 2 global day, 3 interval, 4 phone day,
// 5 phone 30 days, 6 ip day.
var reserveScript = redis.NewScript(`
local function cnt(k) return tonumber(redis.call('GET', k) or '0') end
local function ttl(k) local t = redis.call('PTTL', k); if t < 0 then return 0 end; return t end
if cnt(KEYS[2]) >= tonumber(ARGV[2]) then return {1, ttl(KEYS[2])} end
if cnt(KEYS[1]) >= tonumber(ARGV[1]) then return {2, ttl(KEYS[1])} end
if tonumber(ARGV[3]) > 0 and redis.call('EXISTS', KEYS[3]) == 1 then return {3, ttl(KEYS[3])} end
if cnt(KEYS[4]) >= tonumber(ARGV[4]) then return {4, ttl(KEYS[4])} end
if cnt(KEYS[5]) >= tonumber(ARGV[5]) then return {5, ttl(KEYS[5])} end
if cnt(KEYS[6]) >= tonumber(ARGV[6]) then return {6, ttl(KEYS[6])} end
local function bump(k, ms)
  if redis.call('INCR', k) == 1 then redis.call('PEXPIRE', k, ms) end
end
bump(KEYS[1], ARGV[7])
bump(KEYS[2], ARGV[8])
bump(KEYS[4], ARGV[9])
bump(KEYS[5], ARGV[10])
bump(KEYS[6], ARGV[11])
if tonumber(ARGV[3]) > 0 then redis.call('SET', KEYS[3], '1', 'PX', ARGV[3]) end
return {0, 0}
`)

// releaseScript gives one reservation back; counters never go below zero.
var releaseScript = redis.NewScript(`
for i = 1, 5 do
  if (tonumber(redis.call('GET', KEYS[i]) or '0')) > 0 then redis.call('DECR', KEYS[i]) end
end
redis.call('DEL', KEYS[6])
return 1
`)

// RedisBudget is the Redis-backed domain.SMSBudget.
type RedisBudget struct {
	rdb    redis.Cmdable
	limits domain.SMSLimits
	key    []byte
	now    func() time.Time
}

// NewRedisBudget builds a budget. secret keys the hash under which phones and addresses appear in
// Redis keys (no raw phone numbers are stored by this adapter).
func NewRedisBudget(rdb redis.Cmdable, limits domain.SMSLimits, secret string) *RedisBudget {
	return &RedisBudget{rdb: rdb, limits: limits, key: []byte("authzsvc/sms-budget/v1:" + secret), now: time.Now}
}

func (b *RedisBudget) hash(kind, v string) string {
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(v))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func (b *RedisBudget) keys(t domain.SMSTarget) []string {
	now := b.now().UTC()
	ip := t.IP
	if ip == "" {
		ip = "unknown" // no address: all such callers share one bucket (fail closed)
	}
	ph := b.hash("phone", t.Phone)
	return []string{
		"sms:g:d:" + now.Format("20060102"),
		"sms:g:m:" + now.Format("200601"),
		"sms:p:iv:" + ph,
		"sms:p:d:" + ph,
		"sms:p:m:" + ph,
		"sms:ip:d:" + b.hash("ip", ip),
	}
}

func unavailable(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", domain.ErrSMSUnavailable, fmt.Sprintf(format, args...))
}

// Reserve implements domain.SMSBudget.
func (b *RedisBudget) Reserve(ctx context.Context, t domain.SMSTarget) error {
	l := b.limits
	res, err := reserveScript.Run(ctx, b.rdb, b.keys(t),
		l.GlobalDailyCap, l.GlobalMonthlyCap, l.MinIntervalPerPhone.Milliseconds(),
		l.MaxPerPhonePerDay, l.MaxPerPhonePer30Days, l.MaxPerIPPerDay,
		globalDayTTL.Milliseconds(), globalMonthTTL.Milliseconds(),
		phoneDayWindow.Milliseconds(), phoneMonthWindow.Milliseconds(), ipDayWindow.Milliseconds(),
	).Int64Slice()
	if err != nil || len(res) != 2 {
		return unavailable("budget store: %v", err)
	}
	retry := time.Duration(res[1]) * time.Millisecond
	switch res[0] {
	case 0:
		return nil
	case 1:
		b.logExhausted(ctx, "monthly", l.GlobalMonthlyCap, b.now().UTC().Format("200601"))
		return unavailable("monthly cap reached")
	case 2:
		b.logExhausted(ctx, "daily", l.GlobalDailyCap, b.now().UTC().Format("20060102"))
		return unavailable("daily cap reached")
	case 3:
		return &domain.SMSLimitError{Kind: domain.SMSLimitPhoneInterval, RetryAfter: retry}
	case 4:
		return &domain.SMSLimitError{Kind: domain.SMSLimitPhoneDay, RetryAfter: retry}
	case 5:
		return &domain.SMSLimitError{Kind: domain.SMSLimitPhoneMonth, RetryAfter: retry}
	case 6:
		return &domain.SMSLimitError{Kind: domain.SMSLimitIPDay, RetryAfter: retry}
	}
	return unavailable("unexpected budget answer %d", res[0])
}

// logExhausted logs at ERROR once per period.
func (b *RedisBudget) logExhausted(ctx context.Context, period string, cap int, id string) {
	first, err := b.rdb.SetNX(ctx, "sms:logged:"+period+":"+id, "1", globalDayTTL).Result()
	if err == nil && !first {
		return
	}
	log.Printf("ERROR: SMS budget exhausted: %s cap of %d reached, no SMS will be sent until it resets", period, cap)
}

// Release implements domain.SMSBudget.
func (b *RedisBudget) Release(ctx context.Context, t domain.SMSTarget) error {
	return releaseScript.Run(ctx, b.rdb, b.keys(t)).Err()
}

// RecordSent implements domain.SMSBudget.
func (b *RedisBudget) RecordSent(ctx context.Context) error {
	now := b.now().UTC()
	pipe := b.rdb.TxPipeline()
	dayKey, monthKey := "sms:sent:d:"+now.Format("20060102"), "sms:sent:m:"+now.Format("200601")
	pipe.Incr(ctx, dayKey)
	pipe.Expire(ctx, dayKey, sentDayTTL)
	pipe.Incr(ctx, monthKey)
	pipe.Expire(ctx, monthKey, sentMonthTTL)
	_, err := pipe.Exec(ctx)
	return err
}

// Usage implements domain.SMSBudget.
func (b *RedisBudget) Usage(ctx context.Context) (domain.SMSUsage, error) {
	now := b.now().UTC()
	get := func(key string) (int64, error) {
		v, err := b.rdb.Get(ctx, key).Result()
		if err == redis.Nil {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(v, 10, 64)
	}
	day, err := get("sms:sent:d:" + now.Format("20060102"))
	if err != nil {
		return domain.SMSUsage{}, err
	}
	month, err := get("sms:sent:m:" + now.Format("200601"))
	if err != nil {
		return domain.SMSUsage{}, err
	}
	return domain.SMSUsage{Today: day, Month: month, DailyCap: b.limits.GlobalDailyCap, MonthlyCap: b.limits.GlobalMonthlyCap}, nil
}

var _ domain.SMSBudget = (*RedisBudget)(nil)
