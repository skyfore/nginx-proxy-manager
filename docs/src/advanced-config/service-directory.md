# Service directory API

`GET /api/nginx/proxy-hosts/directory` provides a small, authenticated view for a
custom service directory or homepage. Use an NPM bearer token with proxy-host
view permission. The usual list visibility applies: users limited to their own
hosts cannot see another user's hosts. Disabled and deleted hosts are omitted.

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $NPM_TOKEN" \
  "https://npm-admin.example.com/api/nginx/proxy-hosts/directory"
```

Example response:

```json
[
  {
    "id": 12,
    "domain_names": ["app.example.com", "*.apps.example.com"],
    "urls": ["https://app.example.com"]
  }
]
```

Each entry has exactly three fields:

- `id`: the proxy-host ID, suitable as a stable directory key
- `domain_names`: the configured names, including wildcard patterns
- `urls`: browser links for concrete names, with HTTPS before HTTP

HTTPS is included only when the host has an attached, non-deleted certificate.
HTTP is included unless that certificate is present and Force SSL is enabled.
An HTTPS upstream does not imply a public HTTPS listener. Wildcards, regex
patterns, catch-all names and malformed hostnames never generate links. A host
with only patterns is still returned with an empty `urls` array. Domain names
are labels: render them as text, never as HTML. NPM does not store a service
display name; clients can use the first domain name as a label or maintain their
own labels keyed by `id`.

URLs describe NPM's standard HTTP/HTTPS listeners (ports 80/443), not a verified
external address. DNS, certificate validity, application health, access-list
rules, custom Nginx configuration, CDN TLS termination and non-standard public
port mappings can affect reachability. Configure any external URL overrides in
your directory application. These entries are configuration, not health checks.

No filtering or expansion query parameters are supported. The response never
includes upstream addresses or ports, advanced Nginx configuration, locations,
owner details, access lists, or certificate metadata. The normal proxy-host API
is unchanged. An empty visible directory returns `[]`.

## Keep the NPM token on your server

Fetch this endpoint from your directory's backend. Do not embed an NPM token in
browser JavaScript or a public page. This endpoint is not anonymous and does not
create a directory-only token scope: the same token can still access other NPM
APIs allowed by its existing permissions, including the raw proxy-host list.
Use a dedicated least-privilege account and protect the NPM management interface.
If you publish a directory, explicitly choose which domains and links may be
public; authentication here does not make configured domain names public data.

## Development checks

From `backend`, with the existing dependencies installed and Node 22.3+:

```sh
node --test test/proxy-host-directory-projection.test.js
node --experimental-test-module-mocks --test test/proxy-host-directory.test.js
npm run lint
npm run validate-schema
```

The Node tests isolate the database boundary and exercise the real directory
route, authentication middleware, permission delegation and ownership query.
The existing Cypress suite includes live API coverage and requires a running
NPM test environment; see `test/README.md` in the repository.
