import accessListModel from "../../models/access_list.js";
import auditLogModel from "../../models/audit-log.js";
import certificateModel from "../../models/certificate.js";
import deadHostModel from "../../models/dead_host.js";
import proxyHostModel from "../../models/proxy_host.js";
import redirectionHostModel from "../../models/redirection_host.js";
import streamModel from "../../models/stream.js";
import Access from "../access.js";
import { hasUnsafeConfiguration, operationFor, redactResponse, tokenPrefix } from "../api-token-policy.js";
import errs from "../error.js";
import { errorDiagnostics } from "../error-diagnostics.js";
import { express as logger } from "../../logger.js";

const hostModels = {
	proxy_hosts: proxyHostModel,
	redirection_hosts: redirectionHostModel,
	dead_hosts: deadHostModel,
	streams: streamModel,
};
const assertReferences = async (access, record) => {
	for (const [field, resource] of [
		["certificate_id", "certificates"],
		["access_list_id", "access_lists"],
	]) {
		const id = record?.[field];
		if (id === "new" && field === "certificate_id") {
			await access.can("certificates:create", {});
		} else if (id !== undefined && id !== null && Number(id) !== 0) {
			await access.can(`${resource}:get`, Number(id));
			if (resource === "access_lists") {
				const list = await accessListModel.query().findById(Number(id)).withGraphFetched("clients");
				if (hasUnsafeConfiguration(list)) throw new errs.PermissionError();
			}
		}
	}
	for (const location of record?.locations || []) await assertReferences(access, location);
};

// Check every affected object BEFORE calling any legacy mutation handler.
// Existing ACL/certificate operations can regenerate other hosts as a side effect.
export const authorizeMutation = async (access, operation, body) => {
	if (body?.owner_user_id !== undefined || hasUnsafeConfiguration(body)) throw new errs.PermissionError();
	const existing =
		operation.id && hostModels[operation.resource]
			? await hostModels[operation.resource].query().findById(operation.id)
			: null;
	if (operation.resource === "access_lists" && operation.id && operation.method !== "DELETE") {
		const list = await accessListModel.query().findById(operation.id).withGraphFetched("clients");
		if (hasUnsafeConfiguration(list)) throw new errs.PermissionError();
	}
	if (existing && operation.method !== "DELETE" && hasUnsafeConfiguration(existing)) throw new errs.PermissionError();
	if (hostModels[operation.resource] && operation.method !== "DELETE") {
		await assertReferences(access, existing);
		await assertReferences(access, body);
	}
	if (operation.resource === "access_lists" && operation.id) {
		const hosts = await proxyHostModel.query().where("is_deleted", 0);
		for (const host of hosts) {
			if (
				host.access_list_id === operation.id ||
				host.locations?.some((location) => location.access_list_id === operation.id)
			) {
				if (hasUnsafeConfiguration(host)) throw new errs.PermissionError();
				await assertReferences(access, host);
				await access.can("proxy_hosts:update", host.id);
			}
		}
	}
	const creatingCertificate = operation.resource === "certificates" || body?.certificate_id === "new";
	if (creatingCertificate) {
		const certificate =
			operation.resource === "certificates" && operation.id
				? await certificateModel.query().findById(operation.id)
				: null;
		const domains = (body?.domain_names || certificate?.domain_names || existing?.domain_names || []).map(
			(domain) => domain.toLowerCase(),
		);
		for (const [resource, model] of Object.entries(hostModels)) {
			const hosts = await model.query().where("is_deleted", 0);
			for (const host of hosts) {
				if (
					(certificate && host.certificate_id === certificate.id) ||
					host.domain_names?.some((domain) => domains.includes(domain.toLowerCase()))
				) {
					if (hasUnsafeConfiguration(host)) throw new errs.PermissionError();
					await assertReferences(access, host);
					await access.can(`${resource}:update`, host.id);
				}
			}
		}
	}
};

export default async (req, res, next) => {
	if (typeof res.locals.token !== "string" || !res.locals.token.startsWith(tokenPrefix)) return next();
	// Install before authentication, so failures never expose diagnostic objects.
	const json = res.json.bind(res);
	res.json = (body) => json(redactResponse(body));
	try {
		const access = new Access(res.locals.token);
		await access.load();
		res.locals.access = access;
		const operation = operationFor(req.method, req.path.replace(/\/$/, ""));
		if (!operation || (req.query.expand !== undefined && req.query.expand !== "")) throw new errs.PermissionError();
		const action =
			operation.mode === "read"
				? operation.id
					? "get"
					: "list"
				: req.method === "DELETE"
					? "delete"
					: operation.id
						? "update"
						: "create";
		await access.can(`${operation.resource}:${action}`, operation.id || undefined);
		if (operation.mode === "write") await authorizeMutation(access, { ...operation, method: req.method }, req.body);
		let responseId = operation.id;
		res.json = (body) => {
			responseId = responseId || body?.id;
			return json(redactResponse(body));
		};
		res.on("finish", () => {
			if (operation.mode !== "write" || res.statusCode >= 400) return;
			void auditLogModel
				.query()
				.insert({
					user_id: access.token.getUserId(),
					action: "api-token-used",
					object_type: operation.resource,
					object_id: responseId || 0,
					meta: { api_token_id: access.getApiTokenId(), method: req.method },
				})
				.catch((err) => {
					// Resource audit remains authoritative, but secondary audit failures
					// should still be diagnosable without leaking database parameters.
					logger.warn("API token usage audit failed", errorDiagnostics(err));
				});
		});
		next();
	} catch (err) {
		next(err);
	}
};
