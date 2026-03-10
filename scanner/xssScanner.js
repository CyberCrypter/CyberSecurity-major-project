const axios = require("axios");

async function scanXSS(url){
	const payload = "<script>alert(1)</script>";

	try{
		const target = new URL(url);
		target.searchParams.set("q", payload);

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

		const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
		if (body.includes(payload)) {
			return "Possible XSS";
		}

		return "No XSS detected";
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

module.exports = scanXSS;