# MCP AIO Tests Server

A Model Context Protocol (MCP) server that provides integration with AIO Tests for Jira to retrieve test cases with detailed information including preconditions, steps, and expected results.

## Features

- **Get test cases for Jira issue**: Retrieve all test cases linked to a specific Jira issue
- **Get detailed test case information**: Get comprehensive details for individual test cases
- **List all project test cases**: Browse all test cases in a project with optional detailed information

## Installation

```bash
cd mcp-aio-tests
npm install
npm run build
```

## Usage

### Configuration

Add the MCP server to your Claude Code configuration:

```json
{
  "mcpServers": {
    "aio-tests": {
      "command": "node",
      "args": ["/path/to/mcp-aio-tests/dist/index.js"]
    }
  }
}
```

### Available Tools

#### 1. `get_test_cases_for_issue`

Retrieves all test cases linked to a specific Jira issue with complete details.

**Parameters:**
- `projectKey` (string): Jira project key (e.g., "CB")
- `jiraIssueId` (string): Internal Jira issue ID (e.g., "10100" for CB-76)
- `authToken` (string): AIO Tests authentication token

**Example:**
```typescript
// Get test cases for CB-76 (internal ID: 10100)
{
  "projectKey": "CB",
  "jiraIssueId": "10100",
  "authToken": "your-aio-tests-token"
}
```

#### 2. `get_test_case_detail`

Gets detailed information for a specific test case.

**Parameters:**
- `projectKey` (string): Jira project key
- `testCaseId` (number): Test case ID from AIO Tests
- `authToken` (string): AIO Tests authentication token

#### 3. `list_all_test_cases`

Lists all test cases for a project.

**Parameters:**
- `projectKey` (string): Jira project key
- `authToken` (string): AIO Tests authentication token
- `includeDetails` (boolean, optional): Include detailed steps and results

## Authentication

To get your AIO Tests authentication token:

1. Go to AIO Tests in Jira
2. Navigate to "My Settings"
3. Generate an API Token
4. Use this token in the MCP server calls

## Output Format

The server returns test cases in a structured markdown format including:

- Test case key and title
- Description and preconditions
- Status and script type information
- Linked Jira requirements
- Detailed test steps with expected results
- Tags and metadata (creation/update dates)

## Example Response

```markdown
## CB-TC-60: Implementação de Login de Usuário com Token JWT

**Description:** Verificar se o usuário consegue realizar o login e receber um token JWT com credenciais válidas.

**Status:** Published
**Script Type:** Classic
**Linked Requirements:** 10100

**Test Steps:**
1. **Step:** Acessar a página de login da API
   **Expected Result:** Deve exibir o formulário de login com campos para usuário e senha

2. **Step:** Preencher o campo de usuário com um nome de usuário válido
   **Expected Result:** O campo deve aceitar o nome de usuário sem erros

...
```

## Development

```bash
# Development mode
npm run dev

# Build
npm run build

# Start server
npm start
```

## Error Handling

The server provides comprehensive error handling for:
- Invalid authentication tokens
- Missing or invalid parameters
- AIO Tests API errors
- Network connectivity issues

## Requirements

- Node.js 18+
- TypeScript 5+
- Valid AIO Tests authentication token
- Access to Jira instance with AIO Tests plugin