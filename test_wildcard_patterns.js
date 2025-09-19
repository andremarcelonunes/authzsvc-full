/**
 * Test wildcard patterns for CB-191 acceptance criteria
 * Tests /admin/* patterns to ensure proper wildcard support
 */

const { test, expect } = require('@playwright/test');

const BASE_URL = "http://localhost:8080";

// Helper function to create admin token for testing
async function createAdminToken() {
  const response = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: "admin@example.com",
      password: "admin123"
    })
  });
  
  if (!response.ok) {
    throw new Error(`Failed to login admin: ${response.status}`);
  }
  
  const data = await response.json();
  return data.data.access_token;
}

// Wildcard pattern test cases
const wildcardTests = [
  {
    testCase: "W01",
    description: "Admin accessing /admin/users with /* wildcard pattern",
    policy: "role_admin, /admin/*, GET, *",
    envoyRequest: {
      method: "GET",
      path: "/admin/users",
      headers: { authorization: "ADMIN_TOKEN" }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "/admin/users matches /admin/* wildcard pattern"
  },
  {
    testCase: "W02", 
    description: "Admin accessing /admin/policies with /* wildcard pattern",
    policy: "role_admin, /admin/*, GET, *",
    envoyRequest: {
      method: "GET",
      path: "/admin/policies",
      headers: { authorization: "ADMIN_TOKEN" }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "/admin/policies matches /admin/* wildcard pattern"
  },
  {
    testCase: "W03",
    description: "Admin accessing /admin/settings/config with /* wildcard pattern",
    policy: "role_admin, /admin/*, GET, *",
    envoyRequest: {
      method: "GET", 
      path: "/admin/settings/config",
      headers: { authorization: "ADMIN_TOKEN" }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "/admin/settings/config matches /admin/* wildcard pattern"
  },
  {
    testCase: "W04",
    description: "User should NOT access /admin/* endpoints",
    policy: "role_admin, /admin/*, GET, *",
    envoyRequest: {
      method: "GET",
      path: "/admin/users",
      headers: { authorization: "USER_TOKEN" }
    },
    expectedStatus: 403,
    expectedResult: "DENY",
    reasoning: "User role should not match admin policy"
  },
  {
    testCase: "W05",
    description: "Admin accessing non-admin endpoint should fail if no other policies",
    policy: "role_admin, /admin/*, GET, *",
    envoyRequest: {
      method: "GET",
      path: "/users/123",
      headers: { authorization: "ADMIN_TOKEN" }
    },
    expectedStatus: 403,
    expectedResult: "DENY", 
    reasoning: "/users/123 does NOT match /admin/* pattern"
  }
];

test.describe('Wildcard Pattern Tests for CB-191', () => {
  let adminToken;
  let userToken;
  
  test.beforeAll(async () => {
    try {
      // Get admin token
      adminToken = await createAdminToken();
      console.log('✅ Admin token obtained for wildcard testing');
      
      // Get user token for negative test
      const userResponse = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: "user@example.com",
          password: "user123"
        })
      });
      
      if (userResponse.ok) {
        const userData = await userResponse.json();
        userToken = userData.data.access_token;
        console.log('✅ User token obtained for negative testing');
      }
    } catch (error) {
      console.error('❌ Failed to get tokens:', error.message);
      throw error;
    }
  });

  // Execute each wildcard test case
  wildcardTests.forEach((testCase) => {
    test(`${testCase.testCase}: ${testCase.description}`, async ({ request }) => {
      
      // Replace token placeholders with actual tokens
      let authHeader = testCase.envoyRequest.headers?.authorization;
      if (authHeader === "ADMIN_TOKEN") {
        authHeader = `Bearer ${adminToken}`;
      } else if (authHeader === "USER_TOKEN") {
        authHeader = `Bearer ${userToken}`;
      }
      
      // Prepare Envoy ext_authz request format
      const envoyRequest = {
        attributes: {
          request: {
            http: {
              method: testCase.envoyRequest.method,
              path: testCase.envoyRequest.path,
              headers: {
                ...testCase.envoyRequest.headers,
                ...(authHeader && { authorization: authHeader })
              }
            }
          }
        }
      };
      
      console.log(`\n🧪 ${testCase.testCase}: ${testCase.description}`);
      console.log(`📋 Policy: ${testCase.policy}`);
      console.log(`🎯 Expected: ${testCase.expectedResult} (${testCase.expectedStatus})`);
      console.log(`💭 Reasoning: ${testCase.reasoning}`);
      
      // Make request to external authorization endpoint
      const response = await request.post(`${BASE_URL}/external/authz`, {
        data: envoyRequest
      });
      
      const responseBody = await response.json();
      const actualStatus = responseBody.status?.code || response.status();
      
      console.log(`📊 Actual: ${actualStatus === 200 ? 'ALLOW' : actualStatus === 401 ? 'UNAUTHORIZED' : 'DENY'} (${actualStatus})`);
      
      if (responseBody.body) {
        console.log(`📝 Error Details: ${responseBody.body}`);
      }
      
      if (responseBody.headers) {
        console.log(`📤 Response Headers: ${JSON.stringify(responseBody.headers)}`);
      }
      
      // Verify the response matches expectations
      expect(actualStatus).toBe(testCase.expectedStatus);
      
      // Additional validations based on expected result
      if (testCase.expectedResult === "ALLOW") {
        expect(responseBody.status.code).toBe(200);
        // Should have user context headers for successful requests
        if (authHeader && !authHeader.includes("invalid")) {
          expect(responseBody.headers).toBeDefined();
        }
      } else if (testCase.expectedResult === "DENY") {
        expect(responseBody.status.code).toBe(403);
        expect(responseBody.body).toContain("error");
      }
      
      console.log(`✅ ${testCase.testCase} PASSED\n`);
    });
  });
  
  test.afterAll(async () => {
    console.log('\n📊 Wildcard Pattern Test Summary:');
    console.log(`📝 Total Test Cases: ${wildcardTests.length}`);
    console.log('🎯 Coverage Areas:');
    console.log('   - Admin wildcard access (/admin/*)'); 
    console.log('   - Deep path matching (/admin/settings/config)');
    console.log('   - Negative access control (user -> admin)');
    console.log('   - Path boundary testing (non-admin paths)');
    console.log('✅ All wildcard pattern scenarios tested!');
  });
});