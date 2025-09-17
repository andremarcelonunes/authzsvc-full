#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { AIOTestsClient } from './aio-client.js';
import { TestCase } from './types.js';

const server = new Server(
  {
    name: 'aio-tests-server',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Initialize AIO Tests client
let aioClient: AIOTestsClient;

// Define available tools
const tools: Tool[] = [
  {
    name: 'get_test_cases_for_issue',
    description: 'Get all test cases linked to a specific Jira issue with their preconditions, steps, and expected results',
    inputSchema: {
      type: 'object',
      properties: {
        projectKey: {
          type: 'string',
          description: 'Jira project key (e.g., CB)',
        },
        jiraIssueId: {
          type: 'string',
          description: 'Internal Jira issue ID (e.g., 10100 for CB-76)',
        },
        authToken: {
          type: 'string',
          description: 'AIO Tests authentication token',
        },
      },
      required: ['projectKey', 'jiraIssueId', 'authToken'],
    },
  },
  {
    name: 'get_test_case_detail',
    description: 'Get detailed information for a specific test case including all steps and expected results',
    inputSchema: {
      type: 'object',
      properties: {
        projectKey: {
          type: 'string',
          description: 'Jira project key (e.g., CB)',
        },
        testCaseId: {
          type: 'number',
          description: 'Test case ID from AIO Tests',
        },
        authToken: {
          type: 'string',
          description: 'AIO Tests authentication token',
        },
      },
      required: ['projectKey', 'testCaseId', 'authToken'],
    },
  },
  {
    name: 'list_all_test_cases',
    description: 'List all test cases for a project with basic information',
    inputSchema: {
      type: 'object',
      properties: {
        projectKey: {
          type: 'string',
          description: 'Jira project key (e.g., CB)',
        },
        authToken: {
          type: 'string',
          description: 'AIO Tests authentication token',
        },
        includeDetails: {
          type: 'boolean',
          description: 'Whether to include detailed steps and results for all test cases',
          default: false,
        },
      },
      required: ['projectKey', 'authToken'],
    },
  },
];

// Format test case for display
function formatTestCase(testCase: TestCase): string {
  let result = `## ${testCase.key}: ${testCase.title}\n\n`;
  
  if (testCase.description) {
    result += `**Description:** ${testCase.description}\n\n`;
  }
  
  if (testCase.precondition) {
    result += `**Preconditions:** ${testCase.precondition}\n\n`;
  }
  
  result += `**Status:** ${testCase.status.name}\n`;
  result += `**Script Type:** ${testCase.scriptType.name}\n`;
  
  if (testCase.jiraRequirementIDs.length > 0) {
    result += `**Linked Requirements:** ${testCase.jiraRequirementIDs.join(', ')}\n`;
  }
  
  if (testCase.steps && testCase.steps.length > 0) {
    result += `\n**Test Steps:**\n`;
    testCase.steps.forEach((step, index) => {
      result += `${index + 1}. **Step:** ${step.step}\n`;
      result += `   **Expected Result:** ${step.expectedResult}\n\n`;
    });
  }
  
  if (testCase.tags.length > 0) {
    result += `**Tags:** ${testCase.tags.join(', ')}\n`;
  }
  
  result += `**Created:** ${new Date(testCase.createdDate).toLocaleDateString()}\n`;
  if (testCase.updatedDate) {
    result += `**Updated:** ${new Date(testCase.updatedDate).toLocaleDateString()}\n`;
  }
  
  return result;
}

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools,
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'get_test_cases_for_issue': {
        const { projectKey, jiraIssueId, authToken } = args as {
          projectKey: string;
          jiraIssueId: string;
          authToken: string;
        };

        aioClient = new AIOTestsClient(authToken);
        const testCases = await aioClient.getTestCasesForJiraIssue(projectKey, jiraIssueId);

        if (testCases.length === 0) {
          return {
            content: [
              {
                type: 'text',
                text: `No test cases found for Jira issue ID ${jiraIssueId} in project ${projectKey}`,
              },
            ],
          };
        }

        const formattedOutput = testCases.map(formatTestCase).join('\n---\n\n');
        
        return {
          content: [
            {
              type: 'text',
              text: `# Test Cases for Jira Issue ID: ${jiraIssueId}\n\n${formattedOutput}`,
            },
          ],
        };
      }

      case 'get_test_case_detail': {
        const { projectKey, testCaseId, authToken } = args as {
          projectKey: string;
          testCaseId: number;
          authToken: string;
        };

        aioClient = new AIOTestsClient(authToken);
        const testCase = await aioClient.getTestCaseDetail(projectKey, testCaseId);

        return {
          content: [
            {
              type: 'text',
              text: formatTestCase(testCase),
            },
          ],
        };
      }

      case 'list_all_test_cases': {
        const { projectKey, authToken, includeDetails = false } = args as {
          projectKey: string;
          authToken: string;
          includeDetails?: boolean;
        };

        aioClient = new AIOTestsClient(authToken);
        
        let testCases: TestCase[];
        if (includeDetails) {
          testCases = await aioClient.getAllTestCasesWithDetails(projectKey);
        } else {
          const response = await aioClient.getTestCasesForProject(projectKey);
          testCases = response.items;
        }

        if (testCases.length === 0) {
          return {
            content: [
              {
                type: 'text',
                text: `No test cases found in project ${projectKey}`,
              },
            ],
          };
        }

        const formattedOutput = includeDetails 
          ? testCases.map(formatTestCase).join('\n---\n\n')
          : testCases.map(tc => `- **${tc.key}:** ${tc.title} (Status: ${tc.status.name})`).join('\n');

        return {
          content: [
            {
              type: 'text',
              text: `# Test Cases for Project: ${projectKey}\n\n${formattedOutput}`,
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AIO Tests MCP server running on stdio');
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});