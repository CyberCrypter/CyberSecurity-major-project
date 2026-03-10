const axios = require("axios");

async function scanSQL(url) {

	const params = ["id", "user", "search", "query", "q", "page"];

	const payloads = [
		"' OR '1'='1",
		"' OR 1=1--",
		"' OR 'a'='a",
		"\" OR \"1\"=\"1",
		"' OR 1=1#",
		"' UNION SELECT NULL--",
		"' AND SLEEP(5)--",
		"' AND 1=2--"
	];

	const sqlErrors = [
		"sql syntax",
		"mysql_fetch",
		"syntax error",
		"warning: mysql",
		"unclosed quotation",
		"postgresql",
		"odbc sql server",
		"sqlite error",
		"database error",
		"mysql"
	];

	let results = [];

	try {

		// -------- BASELINE REQUEST --------
		let baselineRes = await axios.get(url, {
			timeout: 8000,
			validateStatus: () => true,
			headers: { "User-Agent": "WebVulnScanner/1.0" }
		});

		let baselineBody = typeof baselineRes.data === "string"
			? baselineRes.data
			: JSON.stringify(baselineRes.data);

		// -------- WAF DETECTION --------
		const serverHeader = (baselineRes.headers.server || "").toLowerCase();

		if (serverHeader.includes("cloudflare") ||
			serverHeader.includes("sucuri") ||
			serverHeader.includes("akamai")) {
			results.push({
				type: "waf_detected",
				server: serverHeader
			});
		}

		// -------- PARAMETER TESTING --------
		const tasks = [];

		for (const param of params) {

			for (const payload of payloads) {

				tasks.push(testPayload(url, param, payload, baselineBody));

			}

		}

		const responses = await Promise.all(tasks);

		for (const r of responses) {

			if (r) results.push(r);

		}

	} catch (err) {

		return {
			status: "scan_failed",
			error: err.message
		};

	}

	return {
		target: url,
		results
	};

}

// -------- PAYLOAD TEST FUNCTION --------

async function testPayload(url, param, payload, baselineBody) {

	try {

		const target = new URL(url);

		target.searchParams.set(param, payload);

		const start = Date.now();

		const res = await axios.get(target.toString(), {
			timeout: 8000,
			validateStatus: () => true,
			headers: { "User-Agent": "WebVulnScanner/1.0" }
		});

		const duration = Date.now() - start;

		const body = typeof res.data === "string"
			? res.data
			: JSON.stringify(res.data);

		const lower = body.toLowerCase();

		// -------- TIME-BASED DETECTION --------
		if (payload.includes("sleep") && duration > 4000) {

			return {
				parameter: param,
				payload,
				type: "time_based_sql_injection",
				response_time: duration
			};

		}

		// -------- ERROR-BASED DETECTION --------
		for (const err of sqlErrors) {

			if (lower.includes(err)) {

				let db = null;

				if (lower.includes("mysql")) db = "MySQL";
				if (lower.includes("postgres")) db = "PostgreSQL";
				if (lower.includes("sqlite")) db = "SQLite";
				if (lower.includes("odbc")) db = "MSSQL";

				return {
					parameter: param,
					payload,
					type: "error_based_sql_injection",
					database: db,
					evidence: err
				};

			}

		}

		// -------- BOOLEAN DIFFERENCE DETECTION --------
		if (body !== baselineBody) {

			return {
				parameter: param,
				payload,
				type: "boolean_based_sql_injection"
			};

		}

	} catch (err) {

		if (err.code === "ECONNABORTED") {
			return {
				parameter: param,
				payload,
				type: "timeout"
			};
		}

	}

	return null;

}

module.exports = scanSQL;