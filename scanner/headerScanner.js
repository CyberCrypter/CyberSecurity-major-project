const axios = require("axios");

async function scanHeaders(url){

    try{

        const response = await axios.get(url, {
            timeout: 8000,
            validateStatus: () => true,
        });

        if (response.status >= 400) {
            return {
                target: url,
                vulnerabilities: [],
                error: `Target returned status ${response.status}`,
            };
        }

        const headers = response.headers;

        let vulnerabilities = [];

        if(!headers["x-frame-options"])
        vulnerabilities.push("Missing X-Frame-Options");

        if(!headers["content-security-policy"])
        vulnerabilities.push("Missing Content Security Policy");

        if(!headers["x-xss-protection"])
        vulnerabilities.push("Missing X-XSS-Protection");

        if(!headers["strict-transport-security"])
        vulnerabilities.push("Missing HSTS");

        return {
            target:url,
            vulnerabilities:vulnerabilities
        }

    }catch(err){

        return {
            error:"Website not reachable"
        }

    }

}

module.exports = scanHeaders;