/// <reference types="cypress" />

describe('Proxy host directory endpoint', () => {
	let token;
	let hostId;
	const path = '/api/nginx/proxy-hosts/directory';

	before(() => {
		cy.resetUsers();
		cy.getToken().then((tok) => {
			token = tok;
		});
	});

	after(() => {
		if (hostId) {
			cy.task('backendApiDelete', {token, path: `/api/nginx/proxy-hosts/${hostId}`, returnOnError: true});
		}
	});

	it('requires authentication', () => {
		for (const invalidToken of [null, 'invalid-token']) {
			cy.task('backendApiGet', {token: invalidToken, path, returnOnError: true}).then((data) => {
				expect(data).to.have.property('error');
				expect(data.error.code).to.be.oneOf([401, 403]);
			});
		}
	});

	it('returns only directory fields and excludes disabled and deleted hosts', () => {
		cy.task('backendApiPost', {
			token,
			path: '/api/nginx/proxy-hosts',
			data: {
				domain_names: ['directory-test.example.com'],
				forward_scheme: 'https',
				forward_host: '127.0.0.1',
				forward_port: 8443,
				access_list_id: 0,
				certificate_id: 0,
				ssl_forced: false,
				caching_enabled: false,
				block_exploits: false,
				allow_websocket_upgrade: false,
				http2_support: false,
				hsts_enabled: false,
				hsts_subdomains: false,
				advanced_config: '',
				locations: [],
				meta: {}
			}
		}).then((created) => {
			hostId = created.id;
			cy.task('backendApiGet', {token, path: `${path}?expand=owner,certificate,access_list`}).then((entries) => {
				cy.validateSwaggerSchema('get', 200, '/nginx/proxy-hosts/directory', entries);
				for (const entry of entries) {
					expect(entry).to.have.all.keys('id', 'domain_names', 'urls');
				}
				expect(entries.find((entry) => entry.id === hostId)).to.deep.equal({
					id: hostId,
					domain_names: ['directory-test.example.com'],
					urls: ['http://directory-test.example.com']
				});
			});
			cy.task('backendApiPost', {token, path: `/api/nginx/proxy-hosts/${hostId}/disable`});
			cy.task('backendApiGet', {token, path}).then((entries) => {
				expect(entries.some((entry) => entry.id === hostId)).to.equal(false);
			});
			cy.task('backendApiPost', {token, path: `/api/nginx/proxy-hosts/${hostId}/enable`});
			cy.task('backendApiDelete', {token, path: `/api/nginx/proxy-hosts/${hostId}`});
			cy.task('backendApiGet', {token, path}).then((entries) => {
				expect(entries.some((entry) => entry.id === hostId)).to.equal(false);
				hostId = null;
			});
		});
	});
});
