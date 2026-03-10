const axios = require("axios");

async function scanSQL(url){
	const payload = "' OR 1=1--";

	try{
		const target = new URL(url);
		target.searchParams.set("id", payload);

		const res = await axios.get(target.toString(), {
			timeout: 8000,
			validateStatus: () => true,
			headers: { "User-Agent": "WebVulnScanner/1.0" },
		});

		if (res.status >= 500) {
			return `Scan inconclusive (server error ${res.status})`;
		}

		if (res.status === 403 || res.status === 406 || res.status === 429) {
			return `Scan blocked by target/WAF (${res.status})`;
		}

		const body = (typeof res.data === "string" ? res.data : JSON.stringify(res.data)).toLowerCase();
		if (
			body.includes("sql") ||
			body.includes("database") ||
			body.includes("syntax error") ||
			body.includes("mysql") ||
			body.includes("postgres")
		) {
			return "Possible SQL Injection";
		}

		return "No SQL Injection detected";
	}catch(err){
		if (err.code === "ECONNABORTED") {
			return "Scan timeout";
		}

		if (err.code === "ENOTFOUND") {
			return "Host not found";
		}

		return `Scan failed: ${err.message}`;
	}

}

module.exports = scanSQL;