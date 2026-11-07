const path = require('node:path');

module.exports = {
  video: false,
  screenshotOnRunFailure: false,
  defaultCommandTimeout: 15000,
  requestTimeout: 30000,
  responseTimeout: 30000,
  retries: 0,
  e2e: {
    baseUrl: 'http://127.0.0.1:18082',
    specPattern: path.join(__dirname, 'api-tokens.cy.js'),
    supportFile: false,
  },
};
