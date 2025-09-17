#!/usr/bin/env node

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Test the MCP server functionality
async function testMCPServer() {
  console.log('🧪 Testing MCP AIO Tests Server...\n');
  
  const serverPath = join(__dirname, 'dist', 'index.js');
  
  // Start the MCP server
  const serverProcess = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'inherit']
  });
  
  // Test initialize request
  const initRequest = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {
        tools: {}
      },
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    }
  };
  
  // Test list tools request
  const listToolsRequest = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list'
  };
  
  let responses = [];
  
  serverProcess.stdout.on('data', (data) => {
    const lines = data.toString().split('\n').filter(line => line.trim());
    lines.forEach(line => {
      try {
        const response = JSON.parse(line);
        responses.push(response);
        console.log('📨 Server response:', JSON.stringify(response, null, 2));
      } catch (e) {
        // Ignore non-JSON lines
      }
    });
  });
  
  // Send initialization request
  setTimeout(() => {
    console.log('📤 Sending initialize request...');
    serverProcess.stdin.write(JSON.stringify(initRequest) + '\n');
  }, 100);
  
  // Send list tools request
  setTimeout(() => {
    console.log('📤 Sending list tools request...');
    serverProcess.stdin.write(JSON.stringify(listToolsRequest) + '\n');
  }, 500);
  
  // Test with sample tool call (won't work without real token, but will show structure)
  setTimeout(() => {
    const testToolCall = {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'get_test_cases_for_issue',
        arguments: {
          projectKey: 'CB',
          jiraIssueId: '10100',
          authToken: 'test-token'
        }
      }
    };
    
    console.log('📤 Sending test tool call (will fail due to invalid token, but shows structure)...');
    serverProcess.stdin.write(JSON.stringify(testToolCall) + '\n');
  }, 1000);
  
  // Clean up after 3 seconds
  setTimeout(() => {
    console.log('\n✅ MCP Server test completed');
    serverProcess.kill();
    process.exit(0);
  }, 3000);
}

testMCPServer().catch(console.error);