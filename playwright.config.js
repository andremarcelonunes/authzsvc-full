module.exports = {
  testDir: '.',
  testMatch: ['test_decision_table.js', 'test_wildcard_patterns.js'],
  timeout: 30000,
  use: {
    baseURL: 'http://localhost:8080',
    trace: 'retain-on-failure',
  },
  reporter: [['list'], ['html']],
  projects: [
    {
      name: 'external-authz-tests',
      testMatch: ['test_decision_table.js', 'test_wildcard_patterns.js'],
    },
  ],
};