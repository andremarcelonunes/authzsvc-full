/**
 * Comprehensive Decision Table Test for External Authorization
 * Tests all field validation policies created with realistic scenarios
 */

const { test, expect } = require('@playwright/test');

const BASE_URL = "http://localhost:8080";

// Helper function to create user token for testing
async function createUserToken(userId = 1875) {
  const response = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: "user@example.com",
      password: "user123"
    })
  });
  
  if (!response.ok) {
    throw new Error(`Failed to login user: ${response.status}`);
  }
  
  const data = await response.json();
  return data.data.access_token;
}

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

// Decision Table Test Cases
const decisionTable = [
  // Test Case 1: Path Parameter Validation - SUCCESS
  {
    testCase: "T01",
    description: "User accessing own profile via path parameter",
    policy: "role_user, /profile/:user_id, GET, path.user_id==token.user_id",
    envoyRequest: {
      method: "GET",
      path: "/profile/1875",
      headers: { authorization: "USER_TOKEN" }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "path.user_id (1875) matches token.user_id (1875)"
  },
  
  // Test Case 2: Path Parameter Validation - FAILURE
  {
    testCase: "T02", 
    description: "User accessing another user's profile",
    policy: "role_user, /profile/:user_id, GET, path.user_id==token.user_id",
    envoyRequest: {
      method: "GET",
      path: "/profile/9999",
      headers: { authorization: "USER_TOKEN" }
    },
    expectedStatus: 403,
    expectedResult: "DENY",
    reasoning: "path.user_id (9999) != token.user_id (1875)"
  },
  
  // Test Case 3: Query String Validation - SUCCESS
  {
    testCase: "T03",
    description: "User accessing data with correct query parameter",
    policy: "role_user, /api/data, GET, query.user_id==token.user_id",
    envoyRequest: {
      method: "GET", 
      path: "/api/data",
      query: "user_id=1875&format=json",
      headers: { authorization: "USER_TOKEN" }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "query.user_id (1875) matches token.user_id (1875)"
  },
  
  // Test Case 4: Query String Validation - FAILURE
  {
    testCase: "T04",
    description: "User accessing data with wrong query parameter",
    policy: "role_user, /api/data, GET, query.user_id==token.user_id", 
    envoyRequest: {
      method: "GET",
      path: "/api/data",
      query: "user_id=9999&format=json",
      headers: { authorization: "USER_TOKEN" }
    },
    expectedStatus: 403,
    expectedResult: "DENY",
    reasoning: "query.user_id (9999) != token.user_id (1875)"
  },
  
  // Test Case 5: Body Field Validation - SUCCESS
  {
    testCase: "T05",
    description: "User creating post with own author_id",
    policy: "role_user, /api/posts, POST, body.author_id==token.user_id",
    envoyRequest: {
      method: "POST",
      path: "/api/posts",
      headers: { 
        authorization: "USER_TOKEN",
        "content-type": "application/json"
      },
      body: JSON.stringify({ title: "My Post", author_id: 1875, content: "Test content" })
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "body.author_id (1875) matches token.user_id (1875)"
  },
  
  // Test Case 6: Body Field Validation - FAILURE
  {
    testCase: "T06",
    description: "User trying to create post as another user",
    policy: "role_user, /api/posts, POST, body.author_id==token.user_id",
    envoyRequest: {
      method: "POST",
      path: "/api/posts", 
      headers: {
        authorization: "USER_TOKEN",
        "content-type": "application/json"
      },
      body: JSON.stringify({ title: "Fake Post", author_id: 9999, content: "Impersonation attempt" })
    },
    expectedStatus: 403,
    expectedResult: "DENY",
    reasoning: "body.author_id (9999) != token.user_id (1875)"
  },
  
  // Test Case 7: Header Validation - SUCCESS  
  {
    testCase: "T07",
    description: "User uploading file with correct x-user-id header",
    policy: "role_user, /api/upload, POST, header.x-user-id==token.user_id",
    envoyRequest: {
      method: "POST",
      path: "/api/upload",
      headers: {
        authorization: "USER_TOKEN",
        "x-user-id": "1875",
        "content-type": "multipart/form-data"
      }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW", 
    reasoning: "header.x-user-id (1875) matches token.user_id (1875)"
  },
  
  // Test Case 8: Header Validation - FAILURE
  {
    testCase: "T08",
    description: "User uploading file with wrong x-user-id header",
    policy: "role_user, /api/upload, POST, header.x-user-id==token.user_id",
    envoyRequest: {
      method: "POST",
      path: "/api/upload",
      headers: {
        authorization: "USER_TOKEN",
        "x-user-id": "9999",
        "content-type": "multipart/form-data"
      }
    },
    expectedStatus: 403,
    expectedResult: "DENY",
    reasoning: "header.x-user-id (9999) != token.user_id (1875)"
  },
  
  // Test Case 9: Multi-Field Validation - SUCCESS
  {
    testCase: "T09",
    description: "User updating secure resource with matching path and body",
    policy: "role_user, /api/secure/:id, PUT, path.id==token.user_id&&body.owner_id==token.user_id",
    envoyRequest: {
      method: "PUT",
      path: "/api/secure/1875",
      headers: {
        authorization: "USER_TOKEN",
        "content-type": "application/json"
      },
      body: JSON.stringify({ owner_id: 1875, data: "secure update" })
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "path.id (1875) matches token.user_id (1875) AND body.owner_id (1875) matches token.user_id (1875)"
  },
  
  // Test Case 10: Multi-Field Validation - FAILURE (path mismatch)
  {
    testCase: "T10",
    description: "User updating secure resource with wrong path id",
    policy: "role_user, /api/secure/:id, PUT, path.id==token.user_id&&body.owner_id==token.user_id",
    envoyRequest: {
      method: "PUT", 
      path: "/api/secure/9999",
      headers: {
        authorization: "USER_TOKEN",
        "content-type": "application/json"
      },
      body: JSON.stringify({ owner_id: 1875, data: "unauthorized update" })
    },
    expectedStatus: 403,
    expectedResult: "DENY",
    reasoning: "path.id (9999) != token.user_id (1875) even though body.owner_id matches"
  },
  
  // Test Case 11: Multi-Field Validation - FAILURE (body mismatch)
  {
    testCase: "T11",
    description: "User updating secure resource with wrong body owner_id",
    policy: "role_user, /api/secure/:id, PUT, path.id==token.user_id&&body.owner_id==token.user_id",
    envoyRequest: {
      method: "PUT",
      path: "/api/secure/1875", 
      headers: {
        authorization: "USER_TOKEN",
        "content-type": "application/json"
      },
      body: JSON.stringify({ owner_id: 9999, data: "impersonation attempt" })
    },
    expectedStatus: 403,
    expectedResult: "DENY",
    reasoning: "path.id matches but body.owner_id (9999) != token.user_id (1875)"
  },
  
  // Test Case 12: Role-based Header Validation - SUCCESS (Admin)
  {
    testCase: "T12",
    description: "Admin accessing admin-data with correct role header",
    policy: "role_user, /api/admin-data, GET, header.x-required-role==token.role",
    envoyRequest: {
      method: "GET",
      path: "/api/admin-data",
      headers: {
        authorization: "ADMIN_TOKEN",
        "x-required-role": "admin"
      }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "header.x-required-role (admin) matches token.role (admin)"
  },
  
  // Test Case 13: No Authorization Header - FAILURE  
  {
    testCase: "T13",
    description: "Request without authorization header",
    policy: "ANY",
    envoyRequest: {
      method: "GET",
      path: "/api/data",
      headers: {}
    },
    expectedStatus: 401,
    expectedResult: "UNAUTHORIZED",
    reasoning: "Missing authorization header"
  },
  
  // Test Case 14: Invalid Token - FAILURE
  {
    testCase: "T14", 
    description: "Request with invalid JWT token",
    policy: "ANY",
    envoyRequest: {
      method: "GET",
      path: "/api/data",
      headers: { authorization: "Bearer invalid.jwt.token" }
    },
    expectedStatus: 401,
    expectedResult: "UNAUTHORIZED", 
    reasoning: "Invalid JWT token format"
  },
  
  // Test Case 15: Existing User Resource Access - SUCCESS
  {
    testCase: "T15",
    description: "User accessing own user resource (existing policy)",
    policy: "role_user, /users/:id, GET, path.id==token.user_id",
    envoyRequest: {
      method: "GET",
      path: "/users/1875",
      headers: { authorization: "USER_TOKEN" }
    },
    expectedStatus: 200,
    expectedResult: "ALLOW",
    reasoning: "Existing policy: path.id (1875) matches token.user_id (1875)"
  }
];

// Main test execution
test.describe('External Authorization Decision Table Tests', () => {
  let userToken;
  let adminToken;
  
  test.beforeAll(async () => {
    // Get fresh tokens for testing
    try {
      userToken = await createUserToken();
      console.log('✅ User token obtained for testing');
      
      adminToken = await createAdminToken();
      console.log('✅ Admin token obtained for testing');
    } catch (error) {
      console.error('❌ Failed to get tokens:', error.message);
      throw error;
    }
  });

  // Execute each test case from decision table
  decisionTable.forEach((testCase, index) => {
    test(`${testCase.testCase}: ${testCase.description}`, async ({ request }) => {
      
      // Replace token placeholders with actual tokens
      let authHeader = testCase.envoyRequest.headers?.authorization;
      if (authHeader === "USER_TOKEN") {
        authHeader = `Bearer ${userToken}`;
      } else if (authHeader === "ADMIN_TOKEN") {
        authHeader = `Bearer ${adminToken}`;
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
      
      // Add query parameters if present
      if (testCase.envoyRequest.query) {
        envoyRequest.attributes.request.http.query = testCase.envoyRequest.query;
      }
      
      // Add body if present (base64 encoded for Envoy format)
      if (testCase.envoyRequest.body) {
        const bodyBase64 = Buffer.from(testCase.envoyRequest.body).toString('base64');
        envoyRequest.attributes.request.http.body = bodyBase64;
      }
      
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
      } else if (testCase.expectedResult === "UNAUTHORIZED") {
        expect(actualStatus).toBe(401);
      }
      
      console.log(`✅ ${testCase.testCase} PASSED\n`);
    });
  });
  
  test.afterAll(async () => {
    console.log('\n📊 Decision Table Test Summary:');
    console.log(`📝 Total Test Cases: ${decisionTable.length}`);
    console.log('🎯 Coverage Areas:');
    console.log('   - Path parameter validation (3 tests)');
    console.log('   - Query string validation (2 tests)');  
    console.log('   - Body field validation (2 tests)');
    console.log('   - Header validation (3 tests)');
    console.log('   - Multi-field validation (3 tests)');
    console.log('   - Error scenarios (2 tests)');
    console.log('✅ All external authorization scenarios tested!');
  });
});