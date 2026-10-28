import assert from "node:assert/strict";
import { test } from "node:test";
import { errorDiagnostics } from "../lib/error-diagnostics.js";

test("diagnostics retain actionable error labels without arbitrary error content", () => {
	const err = Object.assign(new TypeError("PRIVATE_KEY_CANARY"), {
		code: "EACCES",
		status: 500,
		body: "PASSWORD_CANARY",
		previous: new Error("SECRET_CANARY"),
	});
	assert.deepEqual(errorDiagnostics(err), { error: "TypeError", code: "EACCES", status: 500 });
	assert.deepEqual(errorDiagnostics({ name: "SECRET_CANARY", code: "TOKEN_CANARY", status: "500" }), {
		error: "Error",
	});
	assert.deepEqual(errorDiagnostics({ type: "entity.parse.failed", code: 1 }), {
		error: "Error",
		type: "entity.parse.failed",
		exit_code: 1,
	});
	assert.deepEqual(errorDiagnostics({ code: 123456, status: 1000 }), { error: "Error" });
});
