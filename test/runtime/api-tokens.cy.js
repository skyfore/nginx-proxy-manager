/* Genuine browser + HTTP test against a fresh disposable production image.
 * No authentication, API responses, or clipboard implementations are stubbed.
 * Keep credentials out of logs, screenshots, videos, and assertion diagnostics.
 */
describe('Personal API tokens in the production browser application', () => {
  const identity = 'browser-fixture@example.test';
  const password = `Fixture-${crypto.randomUUID()}-Aa1!`;
  let jwt;
  let token;
  let creates = 0;

  const request = (method, url, body, credential) => cy.then({ log: false }, () => cy.request({
    method, url: `/api${url}`, body, log: false, failOnStatusCode: false,
    headers: credential === null ? {} : {
      Authorization: `Bearer ${typeof credential === 'function' ? credential() : credential || jwt}`,
    },
  }));
  const open = () => cy.contains('button', 'Create API Token').click();
  const fill = (name) => {
    cy.get('#api-token-name').type(name);
    cy.get('input[name="api-token-proxy_hosts"]').eq(1).check();
    cy.get('#api-token-password').type(password, { log: false });
  };
  const submit = () => cy.get('[role="dialog"] button[type="submit"]').should('be.enabled').click();
  const list = () => request('GET', '/api-tokens').then(({ status, body }) => {
    expect(status, 'authenticated metadata list status').to.equal(200);
    expect(body.every(row => !('token' in row)), 'list contains metadata only').to.equal(true);
    return body;
  });

  before(() => {
    request('GET', '/', undefined, null).then(({ status, body }) => {
      expect(status).to.equal(200);
      expect(body.setup, 'requires a fresh disposable instance').to.equal(false);
    });
    request('POST', '/users', {
      name: 'Browser fixture', nickname: 'Browser', email: identity,
      auth: { type: 'password', secret: password },
    }, null).then(({ status }) => expect(status).to.equal(201));
    request('POST', '/tokens', { identity, secret: password }, null).then(({ status, body }) => {
      expect(status).to.equal(200);
      jwt = body.token;
    });
  });

  it('logs in, cancels safely, creates once, copies, revokes, and survives interrupted navigation', () => {
    cy.visit('/login');
    cy.get('input[name="email"]').type(identity);
    cy.get('input[name="password"]').type(password, { log: false });
    cy.get('button[type="submit"]').click();
    cy.location('pathname').should('not.equal', '/login');
    cy.visit('/settings/api-tokens');
    cy.contains('h2', 'API Tokens').should('be.visible');

    open();
    fill('cancelled-draft');
    cy.get('[role="dialog"] button[aria-label="Close"]').click();
    cy.get('[role="dialog"]').should('not.exist');
    open();
    cy.get('#api-token-name').should('have.value', '');
    cy.get('#api-token-password').should('have.value', '');
    cy.get('input[name="api-token-proxy_hosts"]').eq(0).should('be.checked');
    list().then(rows => expect(rows.length, 'cancel creates no token').to.equal(0));

    let releaseResponse;
    const responseGate = new Promise(resolve => { releaseResponse = resolve; });
    cy.intercept('POST', '/api/api-tokens', req => {
      creates += 1;
      req.continue(() => responseGate);
    }).as('create');
    fill('browser-created');
    cy.get('[role="dialog"] button[type="submit"]').should('be.enabled').then($button => {
      $button[0].click();
      $button[0].click();
    });
    cy.get('[role="dialog"] fieldset').first().should('have.prop', 'disabled', true);
    cy.then(() => releaseResponse());
    cy.wait('@create', { log: false }).then(({ response }) => {
      expect(response.statusCode).to.equal(201);
      token = response.body.token;
      expect(creates, 'repeated submit produces one request').to.equal(1);
    });
    cy.get('#api-token-secret', { log: false }).then($input => {
      expect($input.val() === token, 'one-time secret matches real API result').to.equal(true);
    });
    cy.then(() => Cypress.automation('remote:debugger:protocol', {
      command: 'Browser.grantPermissions',
      params: { permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'], origin: 'http://127.0.0.1:18082' },
    }));
    cy.contains('button', 'Copy token').click();
    cy.contains('button', 'Copied').should('be.visible');
    cy.window({ log: false }).then(async win => {
      const copied = await win.navigator.clipboard.readText();
      expect(copied === token, 'real browser clipboard contains token').to.equal(true);
      await win.navigator.clipboard.writeText('');
    });
    cy.contains('button', 'I have saved the token').click();
    cy.get('#api-token-secret').should('not.exist');
    list().then(rows => expect(rows.length).to.equal(1));
    request('GET', '/nginx/proxy-hosts', undefined, () => token).then(({ status }) => expect(status).to.equal(200));

    cy.contains('tr', 'browser-created').contains('button', 'Revoke').click();
    cy.get('[role="dialog"]').contains('button', 'Cancel').click();
    request('GET', '/nginx/proxy-hosts', undefined, () => token).then(({ status }) => expect(status).to.equal(200));
    cy.contains('tr', 'browser-created').contains('button', 'Revoke').click();
    cy.get('[role="dialog"]').contains('button', 'Revoke').click();
    cy.contains('tr', 'browser-created').should('contain.text', 'Revoked');
    request('GET', '/nginx/proxy-hosts', undefined, () => token).then(({ status }) => expect(status).to.equal(401));

    open();
    fill('navigation-interrupted');
    submit();
    cy.wait('@create', { log: false }).then(({ response }) => expect(response.statusCode).to.equal(201));
    // Leave the one-time secret screen without acknowledging it. History must not restore it.
    cy.visit('/settings');
    cy.go('back');
    cy.contains('tr', 'navigation-interrupted').should('be.visible');
    cy.get('#api-token-secret').should('not.exist');
    cy.reload();
    cy.get('#api-token-secret').should('not.exist');
    cy.contains('tr', 'navigation-interrupted').contains('button', 'Revoke').click();
    cy.get('[role="dialog"]').contains('button', 'Revoke').click();
    list().then(rows => {
      expect(rows.length, 'no duplicate tokens').to.equal(2);
      expect(rows.every(row => row.revoked_on), 'all browser credentials revoked').to.equal(true);
    });
  });
});
