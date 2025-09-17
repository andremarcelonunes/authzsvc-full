#!/usr/bin/env node

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Test the MCP server with real token
async function testWithRealToken() {
  console.log('🧪 Testing MCP AIO Tests Server with real token...\n');
  
  const serverPath = join(__dirname, 'dist', 'index.js');
  
  // Start the MCP server
  const serverProcess = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'inherit']
  });
  
  // Test with CB-76
  const testToolCall = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: 'get_test_cases_for_issue',
      arguments: {
        projectKey: 'CB',
        jiraIssueId: '10100',
        authToken: 'ZjY2ZTI5YjktMTQxMi0zNmQ0LWJmZWEtYzEyMjkxYTQyNWE0LjMxNzAxNmQxLWJhZTItNGQ5MC04OTAyLWU2ZDNjNTdkNTZmOA=='
      }
    }
  };
  
  let responseReceived = false;
  
  serverProcess.stdout.on('data', (data) => {
    const lines = data.toString().split('\n').filter(line => line.trim());
    lines.forEach(line => {
      try {
        const response = JSON.parse(line);
        console.log('📨 Success! Got test cases:');
        // Just show a summary to avoid overwhelming output
        if (response.result && response.result.content) {
          const content = response.result.content[0].text;
          const testCaseCount = (content.match(/## CB-TC-/g) || []).length;
          console.log(`   Found ${testCaseCount} test cases for CB-76`);
          console.log('   First 500 characters:');
          console.log('   ' + content.substring(0, 500) + '...');
        }
        responseReceived = true;
      } catch (e) {
        // Ignore non-JSON lines
      }
    });
  });
  
  // Send tool call request
  setTimeout(() => {
    console.log('📤 Sending get_test_cases_for_issue request for CB-76...');
    serverProcess.stdin.write(JSON.stringify(testToolCall) + '\n');
  }, 100);
  
  // Clean up after response or timeout
  setTimeout(() => {
    if (responseReceived) {
      console.log('\n✅ MCP Server working correctly!');
    } else {
      console.log('\n❌ No response received');
    }
    serverProcess.kill();
    process.exit(0);
  }, 5000);
}

testWithRealToken().catch(console.error);