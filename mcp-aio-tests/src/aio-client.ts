import fetch from 'node-fetch';
import { TestCase, TestCaseDetail, AIOTestsResponse } from './types.js';

export class AIOTestsClient {
  private baseUrl: string;
  private authToken: string;

  constructor(authToken: string, baseUrl = 'https://tcms.aiojiraapps.com/aio-tcms/api/v1') {
    this.baseUrl = baseUrl;
    this.authToken = authToken;
  }

  private async makeRequest(endpoint: string): Promise<any> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Authorization': `AioAuth ${this.authToken}`,
      'Content-Type': 'application/json'
    };

    const response = await fetch(url, { headers });

    if (!response.ok) {
      throw new Error(`AIO Tests API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  async getTestCasesForProject(projectKey: string, startAt = 0, maxResults = 100): Promise<AIOTestsResponse> {
    return this.makeRequest(`/project/${projectKey}/testcase?startAt=${startAt}&maxResults=${maxResults}`);
  }

  async getTestCaseDetail(projectKey: string, testCaseId: number, needDataInRTF = true): Promise<TestCaseDetail> {
    return this.makeRequest(`/project/${projectKey}/testcase/${testCaseId}/detail?needDataInRTF=${needDataInRTF}`);
  }

  async getTestCasesForJiraIssue(projectKey: string, jiraIssueId: string): Promise<TestCase[]> {
    // Get all test cases for the project
    const response = await this.getTestCasesForProject(projectKey);
    
    // Filter test cases that are linked to the specific Jira issue
    const linkedTestCases = response.items.filter(testCase => 
      testCase.jiraRequirementIDs && testCase.jiraRequirementIDs.includes(jiraIssueId)
    );

    // Get detailed information for each linked test case
    const detailedTestCases: TestCase[] = [];
    for (const testCase of linkedTestCases) {
      try {
        const detail = await this.getTestCaseDetail(projectKey, testCase.ID);
        detailedTestCases.push(detail);
      } catch (error) {
        console.warn(`Failed to get details for test case ${testCase.key}: ${error}`);
        // Include basic info if detailed fetch fails
        detailedTestCases.push(testCase);
      }
    }

    return detailedTestCases;
  }

  async getAllTestCasesWithDetails(projectKey: string): Promise<TestCase[]> {
    const response = await this.getTestCasesForProject(projectKey);
    const detailedTestCases: TestCase[] = [];

    for (const testCase of response.items) {
      try {
        const detail = await this.getTestCaseDetail(projectKey, testCase.ID);
        detailedTestCases.push(detail);
      } catch (error) {
        console.warn(`Failed to get details for test case ${testCase.key}: ${error}`);
        detailedTestCases.push(testCase);
      }
    }

    return detailedTestCases;
  }
}