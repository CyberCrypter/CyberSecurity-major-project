const axios = require("axios");

async function scanXSS(url) {

	const params = ["q", "search", "query", "id", "name", "page", "redirect"];

	const payloads = [
		"<script>alert(1)</script>",
		"\"'><script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<body onload=alert(1)>"
	];

	const domPatterns = [
		"document.location",
		"document.cookie",
		"innerhtml",
		"eval(",
		"location.href"
	];

	let results = [];

	try {

		// -------- BASELINE REQUEST --------
		const baseRes = await axios.get(url, {
			timeout: 8000,
			validateStatus: () => true,
			headers: { "User-Agent": "WebVulnScanner/1.0" }
		});

		const baseBody = typeof baseRes.data === "string"
			? baseRes.data
			: JSON.stringify(baseRes.data);

		const baseLower = baseBody.toLowerCase();

		// -------- DOM XSS DETECTION --------
		for (const pattern of domPatterns) {

			if (baseLower.includes(pattern)) {

				results.push({
					type: "possible_dom_xss",
					pattern
				});

			}

		}

		// -------- WAF DETECTION --------
		const serverHeader = (baseRes.headers.server || "").toLowerCase();

		if (
			serverHeader.includes("cloudflare") ||
			serverHeader.includes("akamai") ||
			serverHeader.includes("sucuri")
		) {
			results.push({
				type: "waf_detected",
				server: serverHeader
			});
		}

		// -------- CSP DETECTION --------
		if (baseRes.headers["content-security-policy"]) {
			results.push({
				type: "csp_detected",
				policy: baseRes.headers["content-security-policy"]
			});
		}

		// -------- PARAMETER & PAYLOAD TESTING --------

		const tasks = [];

		for (const param of params) {

			for (const payload of payloads) {

				tasks.push(testPayload(url, param, payload, baseBody));

			}

		}

		const responses = await Promise.all(tasks);

		for (const r of responses) {

			if (r) results.push(r);

		}

		// -------- STORED XSS RECHECK --------
		const recheck = await axios.get(url, {
			timeout: 8000,
			validateStatus: () => true
		});

		const reBody = typeof recheck.data === "string"
			? recheck.data
			: JSON.stringify(recheck.data);

		for (const payload of payloads) {

			if (reBody.includes(payload)) {

				results.push({
					type: "possible_stored_xss",
					payload
				});

			}

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

async function testPayload(url, param, payload, baseline) {

	try {

		const target = new URL(url);

		target.searchParams.set(param, payload);

		const res = await axios.get(target.toString(), {
			timeout: 8000,
			validateStatus: () => true,
			headers: { "User-Agent": "WebVulnScanner/1.0" }
		});

		const body = typeof res.data === "string"
			? res.data
			: JSON.stringify(res.data);

		// -------- REFLECTED XSS DETECTION --------
		if (body.includes(payload)) {

			return {
				parameter: param,
				payload,
				type: "reflected_xss"
			};

		}

		// -------- ENCODED XSS DETECTION --------
		const encoded = payload
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;");

		if (body.includes(encoded)) {

			return {
				parameter: param,
				payload,
				type: "encoded_reflection"
			};

		}

		// -------- RESPONSE DIFFERENCE --------
		if (body !== baseline) {

			return {
				parameter: param,
				payload,
				type: "response_difference"
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

module.exports = scanXSS;