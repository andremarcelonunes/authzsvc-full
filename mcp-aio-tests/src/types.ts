export interface TestStep {
  ID: number;
  step: string;
  expectedResult: string;
  stepType: string;
}

export interface TestCase {
  ID: number;
  key: string;
  title: string;
  description: string | null;
  precondition: string | null;
  status: {
    ID: number;
    name: string;
    description: string;
  };
  priority: any;
  scriptType: {
    ID: number;
    name: string;
    description: string;
  };
  steps: TestStep[];
  jiraRequirementIDs: string[];
  createdDate: number;
  updatedDate: number | null;
  estimatedEffort: string | null;
  tags: string[];
  ownedByID: string;
}

export interface AIOTestsResponse {
  items: TestCase[];
  totalResults?: number;
  startAt?: number;
  maxResults?: number;
}

export interface TestCaseDetail extends TestCase {
  versions: Array<{
    version: number;
    ID: number;
  }>;
}