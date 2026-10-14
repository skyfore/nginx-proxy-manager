import assert from "node:assert/strict";
import { once } from "node:events";
import { after, before, mock, test } from "node:test";
import express from "express";
import errs from "../lib/error.js";

const host = (overrides = {}) => ({
	id: 1,
	owner_user_id: 10,
	enabled: true,
	is_deleted: false,
	domain_names: ["app.example.com"],
	certificate_id: 0,
	certificate: null,
	ssl_forced: false,
	forward_scheme: "https",
	...overrides,
});

// Exercise the real getAll/getDirectory methods with an isolated model boundary.
// This verifies the existing authorization and ownership query are reused.
let rows = [];
let queryCount = 0;
let expansion;
const model = {
	defaultAllowGraph: "[certificate]",
	query: () => {
		queryCount++;
		let selected = rows;
		const query = {
			where: (key, value) => {
				selected = selected.filter((row) => Number(row[key]) === value);
				return query;
			},
			andWhere: (key, value) => {
				selected = selected.filter((row) => row[key] === value);
				return query;
			},
			groupBy: () => query,
			allowGraph: () => query,
			orderBy: () => query,
			withGraphFetched: (value) => {
				expansion = value;
				return query;
			},
			// biome-ignore lint/suspicious/noThenProperty: Objection query builders are intentionally thenable.
			then: (fn) => Promise.resolve(structuredClone(selected)).then(fn),
		};
		return query;
	},
};
mock.module("../logger.js", { namedExports: { debug: () => {}, express: {} } });
mock.module("../models/proxy_host.js", { defaultExport: model });
mock.module("../lib/helpers.js", { namedExports: { castJsonIfNeed: (value) => value } });
mock.module("../lib/utils.js", { defaultExport: { omitRows: () => (value) => value } });
for (const name of ["audit-log", "certificate", "nginx"]) {
	mock.module(`../internal/${name}.js`, { defaultExport: {} });
}
mock.module("../internal/host.js", { defaultExport: { cleanAllRowsCertificateMeta: (value) => value } });
const internalProxyHost = (await import("../internal/proxy-host.js")).default;

const accessFor = (visibility) => ({
	token: { getUserId: () => 10 },
	can: async (permission) => {
		assert.equal(permission, "proxy_hosts:list");
		if (visibility === "denied") {
			throw Object.assign(new Error("Permission Denied"), { status: 403 });
		}
		return { permission_visibility: visibility };
	},
});

test("directory preserves list permission, ownership visibility and soft-deletion", async () => {
	rows = [
		host(),
		host({ id: 2, owner_user_id: 20 }),
		host({ id: 3, is_deleted: true }),
		host({ id: 4, enabled: false }),
	];
	assert.deepEqual((await internalProxyHost.getDirectory(accessFor("user"))).map((row) => row.id), [1]);
	assert.deepEqual((await internalProxyHost.getDirectory(accessFor("all"))).map((row) => row.id), [1, 2]);
	assert.equal(expansion, "[certificate]");
	const previous = queryCount;
	await assert.rejects(internalProxyHost.getDirectory(accessFor("denied")), /Permission Denied/);
	assert.equal(queryCount, previous, "denied requests must not query hosts");
});

// Keep the real jwt-decode middleware and route, replacing only Access's
// database/token boundary. Live token validation is covered by the Cypress suite.
mock.module("../lib/access.js", {
	defaultExport: class {
		constructor(token) {
			this.tokenString = token;
		}
		async load() {
			const serverKeyErrors = {
				"missing-key": "secret or public key must be provided",
				"invalid-key": "secretOrPublicKey is not valid key material",
				"wrong-key-type": "secretOrPublicKey must be an asymmetric key when using RS256",
			};
			if (serverKeyErrors[this.tokenString]) {
				throw Object.assign(new Error(serverKeyErrors[this.tokenString]), { name: "JsonWebTokenError" });
			}
			if (["malformed", "tampered", "not-yet-valid"].includes(this.tokenString)) {
				throw Object.assign(new Error(this.tokenString === "tampered" ? "invalid signature" : "jwt malformed"), {
					name: this.tokenString === "not-yet-valid" ? "NotBeforeError" : "JsonWebTokenError",
				});
			}
			if (this.tokenString === "expired") {
				throw new errs.AuthError("Token has expired");
			}
			if (this.tokenString === "internal-error") {
				throw new Error("unrelated internal failure");
			}
			if (!this.tokenString || this.tokenString === "invalid") {
				throw Object.assign(new Error("Permission Denied"), { status: 403 });
			}
			Object.assign(this, accessFor(this.tokenString));
		}
	},
});
const router = (await import("../routes/nginx/proxy_hosts.js")).default;
let server;
let base;
before(async () => {
	const app = express();
	app.use((req, res, next) => {
		res.locals.token = req.get("Authorization");
		next();
	});
	app.use("/api/nginx/proxy-hosts", router);
	app.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message }));
	server = app.listen(0, "127.0.0.1");
	await once(server, "listening");
	base = `http://127.0.0.1:${server.address().port}/api/nginx/proxy-hosts/directory`;
});
after(() => new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve())));

test("literal directory route is authenticated, not treated as host_id", async () => {
	rows = [host()];
	for (const token of [null, "invalid", "denied"]) {
		const response = await fetch(base, { headers: token ? { Authorization: token } : {} });
		assert.equal(response.status, 403);
	}
	const response = await fetch(`${base}?expand=owner,access_list&query=ignored`, { headers: { Authorization: "all" } });
	assert.equal(response.status, 200);
	assert.equal(response.headers.get("cache-control"), "no-store");
	assert.deepEqual(await response.json(), [
		{ id: 1, domain_names: ["app.example.com"], urls: ["http://app.example.com"] },
	]);
});

test("directory normalizes only known JWT errors and preserves legacy routes", async () => {
	for (const token of ["malformed", "tampered", "expired", "not-yet-valid"]) {
		const response = await fetch(base, { headers: { Authorization: token } });
		assert.equal(response.status, 401);
		assert.deepEqual(await response.json(), { error: "Invalid or expired authentication" });
	}
	for (const token of ["internal-error", "missing-key", "invalid-key", "wrong-key-type"]) {
		const failure = await fetch(base, { headers: { Authorization: token } });
		assert.equal(failure.status, 500, "server failures must not be disguised as authentication failures");
	}
	const legacy = await fetch(base.replace(/\/directory$/, ""), { headers: { Authorization: "malformed" } });
	assert.equal(legacy.status, 500, "the existing list route retains its authentication behavior");
});
