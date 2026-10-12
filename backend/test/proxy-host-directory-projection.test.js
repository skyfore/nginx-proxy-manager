import assert from "node:assert/strict";
import { test } from "node:test";
import toDirectory from "../lib/proxy-host-directory.js";

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

test("directory allowlists fields and does not mutate input", () => {
	const row = host({
		forward_host: "10.0.0.2",
		forward_port: 8080,
		advanced_config: "secret config",
		meta: { secret: "secret" },
		locations: [{ password: "secret" }],
		access_list: { items: [{ password: "secret" }] },
		owner: { email: "private@example.com" },
		certificate: { id: 7, meta: { dns_provider_credentials: "secret" } },
	});
	const original = structuredClone(row);
	assert.deepEqual(toDirectory([row]), [{
		id: 1,
		domain_names: ["app.example.com"],
		urls: ["https://app.example.com", "http://app.example.com"],
	}]);
	assert.deepEqual(row, original);
});

test("listener URLs use the attached certificate and force-SSL, never upstream scheme", () => {
	for (const forward_scheme of ["http", "https"]) {
		assert.deepEqual(toDirectory([host({ forward_scheme })])[0].urls, ["http://app.example.com"]);
		assert.deepEqual(toDirectory([host({ forward_scheme, certificate: { id: 2 }, ssl_forced: true })])[0].urls,
			["https://app.example.com"]);
	}
	// A missing/deleted certificate relation cannot establish an HTTPS listener.
	assert.deepEqual(toDirectory([host({ certificate_id: 2, ssl_forced: true })])[0].urls,
		["http://app.example.com"]);
});

test("wildcards, patterns and URL injection remain text, never become links", () => {
	const patterns = ["*.example.com", ".example.com", "_", "*", "~example", "bad/path", "a@b.com",
		"a.com:443", "https://a.com", "a.com?x", "a.com#x", "a\\b.com", " a.com", "a.com\n",
		"a..com", "-a.com", "a-.com", "127.1", "2130706433", "0x7f000001", `${"a".repeat(64)}.com`];
	const domains = [...patterns, "APP.example.com", "xn--bcher-kva.example", "home", "127.0.0.1"];
	const entry = toDirectory([host({ domain_names: domains })])[0];
	assert.deepEqual(entry.domain_names, domains);
	assert.deepEqual(entry.urls, [
		"http://APP.example.com",
		"http://xn--bcher-kva.example",
		"http://home",
		"http://127.0.0.1",
	]);
	assert.deepEqual(toDirectory([host({ domain_names: ["*.example.com"] })])[0].urls, []);
});

test("disabled hosts are omitted; empty directories are arrays", () => {
	assert.deepEqual(toDirectory([host({ enabled: false }), host({ enabled: 0 })]), []);
	assert.deepEqual(toDirectory([]), []);
	assert.equal(toDirectory([host({ enabled: 1 })]).length, 1);
});
