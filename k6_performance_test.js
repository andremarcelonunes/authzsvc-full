/**
 * K6 Performance Test for CB-TC-81: Benchmark Authorization Middleware
 * Tests 1000 concurrent GET requests to external authorization endpoint
 * Target: <200ms response time
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const authorizationRate = new Rate('authorization_success_rate');
const authorizationDuration = new Trend('authorization_duration');

// Test configuration
export const options = {
  stages: [
    { duration: '10s', target: 100 },   // Ramp up to 100 users
    { duration: '30s', target: 500 },   // Ramp up to 500 users
    { duration: '60s', target: 1000 },  // Peak load: 1000 concurrent users
    { duration: '30s', target: 500 },   // Ramp down to 500 users
    { duration: '10s', target: 0 },     // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'], // 95% of requests must complete under 200ms
    authorization_success_rate: ['rate>0.99'], // 99% success rate
    authorization_duration: ['p(95)<200'], // 95% of auth requests under 200ms
  },
};

const BASE_URL = 'http://localhost:8080';

// Get authentication tokens before the test
export function setup() {
  console.log('🚀 Setting up K6 performance test for CB-TC-81...');
  
  // Get user token
  const userLoginResponse = http.post(`${BASE_URL}/auth/login`, JSON.stringify({
    email: 'user@example.com',
    password: 'user123'
  }), {
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (userLoginResponse.status !== 200) {
    throw new Error(`Failed to get user token: ${userLoginResponse.status}`);
  }

  const userToken = userLoginResponse.json().data.access_token;
  console.log('✅ User token obtained for performance testing');

  return {
    userToken: userToken,
  };
}

export default function(data) {
  // CB-TC-81 Test: Benchmark 1000 concurrent GET requests to '/users/123'
  const envoyRequest = {
    attributes: {
      request: {
        http: {
          method: 'GET',
          path: '/users/1875', // User ID from our test data
          headers: {
            authorization: `Bearer ${data.userToken}`,
            'content-type': 'application/json'
          }
        }
      }
    }
  };

  const startTime = new Date();
  
  // Send external authorization request (simulating Envoy ext_authz)
  const response = http.post(`${BASE_URL}/external/authz`, JSON.stringify(envoyRequest), {
    headers: {
      'Content-Type': 'application/json',
    },
  });

  const endTime = new Date();
  const duration = endTime - startTime;

  // Record custom metrics
  authorizationDuration.add(duration);
  authorizationRate.add(response.status === 200);

  // Validate response
  const success = check(response, {
    'CB-TC-81: Status is 200 OK': (r) => r.status === 200,
    'CB-TC-81: Response time < 200ms': (r) => r.timings.duration < 200,
    'CB-TC-81: Response contains status': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.status && body.status.code === 200;
      } catch (e) {
        return false;
      }
    },
    'CB-TC-81: Response contains user headers': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.headers && body.headers['x-user-id'] && body.headers['x-user-role'];
      } catch (e) {
        return false;
      }
    },
  });

  if (!success) {
    console.error(`❌ Request failed: Status ${response.status}, Duration: ${duration}ms`);
  }

  // Small sleep to prevent overwhelming the server
  sleep(0.1);
}

export function teardown(data) {
  console.log('📊 K6 Performance Test Results Summary:');
  console.log('🎯 CB-TC-81: Benchmark Authorization Middleware');
  console.log('📈 Target: 1000 concurrent GET requests with <200ms response time');
  console.log('✅ Test completed successfully!');
}

export function handleSummary(data) {
  return {
    'performance_test_results.json': JSON.stringify(data, null, 2),
    stdout: `
🏆 CB-TC-81 Performance Test Results
=====================================

📊 Request Statistics:
   • Total Requests: ${data.metrics.http_reqs.values.count}
   • Success Rate: ${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%
   • Requests/sec: ${data.metrics.http_reqs.values.rate.toFixed(2)}

⏱️  Response Time Metrics:
   • Average: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms
   • 95th Percentile: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms
   • 99th Percentile: ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms
   • Max: ${data.metrics.http_req_duration.values.max.toFixed(2)}ms

🎯 CB-TC-81 Validation:
   • Target: <200ms for 95% of requests
   • Achieved: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms
   • Status: ${data.metrics.http_req_duration.values['p(95)'] < 200 ? '✅ PASSED' : '❌ FAILED'}

🚀 Authorization Performance:
   • Authorization Success Rate: ${((1 - data.metrics.authorization_success_rate?.values?.rate || 0) * 100).toFixed(2)}%
   • Authorization 95th Percentile: ${data.metrics.authorization_duration?.values?.['p(95)']?.toFixed(2) || 'N/A'}ms

=====================================
`,
  };
}