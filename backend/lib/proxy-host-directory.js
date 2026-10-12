/**
 * Return navigable DNS names only. Nginx server names can also contain wildcard,
 * regex and catch-all patterns, none of which are safe browser destinations.
 */
const isLinkableDomain = (domain) => {
	if (typeof domain !== "string" || domain.length > 253) {
		return false;
	}
	const labels = domain.replace(/\.$/, "").split(".");
	if (!labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) {
		return false;
	}
	try {
		// Reject numeric hostnames that browsers reinterpret as a different IP.
		return new URL(`http://${domain}`).hostname === domain.toLowerCase();
	} catch {
		return false;
	}
};

/**
 * Strict allowlist: never spread a host or return its expanded relations.
 * URLs describe NPM's standard listeners, not the upstream forward_scheme.
 * Deleted hosts have already been excluded by getAll's permission-aware query.
 */
export default (rows) =>
	rows
		.filter((row) => row.enabled === true || row.enabled === 1)
		.map((row) => {
			const schemes = [];
			if (row.certificate) {
				schemes.push("https");
			}
			if (!row.certificate || !(row.ssl_forced === true || row.ssl_forced === 1)) {
				schemes.push("http");
			}
			const domainNames = row.domain_names.filter((domain) => typeof domain === "string");
			return {
				id: row.id,
				domain_names: domainNames,
				urls: domainNames.filter(isLinkableDomain).flatMap((domain) => schemes.map((scheme) => `${scheme}://${domain}`)),
			};
		});
