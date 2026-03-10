const axios = require("axios");

async function scanHeaders(url) {

    try {

        const response = await axios.head(url, {
            timeout: 8000,
            maxRedirects: 5,
            validateStatus: () => true,
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*"
            }
        });

        const headers = response.headers;

        let missingHeaders = [];
        let misconfiguredHeaders = [];
        let infoDisclosure = [];
        let cookieIssues = [];
        let vulnerabilities = [];

        // -------- HTTPS CHECK --------
        if (!url.startsWith("https")) {
            vulnerabilities.push("Site not using HTTPS");
        }

        // -------- SECURITY HEADERS --------
        if (!headers["x-frame-options"])
            missingHeaders.push("X-Frame-Options");

        if (!headers["content-security-policy"])
            missingHeaders.push("Content-Security-Policy");

        if (!headers["x-xss-protection"])
            missingHeaders.push("X-XSS-Protection");

        if (!headers["strict-transport-security"])
            missingHeaders.push("Strict-Transport-Security (HSTS)");

        if (!headers["x-content-type-options"])
            missingHeaders.push("X-Content-Type-Options");

        if (!headers["referrer-policy"])
            missingHeaders.push("Referrer-Policy");

        if (!headers["permissions-policy"])
            missingHeaders.push("Permissions-Policy");

        if (!headers["cross-origin-opener-policy"])
            missingHeaders.push("Cross-Origin-Opener-Policy");

        if (!headers["cross-origin-resource-policy"])
            missingHeaders.push("Cross-Origin-Resource-Policy");

        // -------- WEAK HEADER VALUES --------
        if (headers["x-frame-options"]) {
            const value = headers["x-frame-options"].toLowerCase();

            if (!value.includes("deny") && !value.includes("sameorigin")) {
                misconfiguredHeaders.push("Weak X-Frame-Options value");
            }
        }

        if (headers["strict-transport-security"]) {

            const hsts = headers["strict-transport-security"];

            if (!hsts.includes("max-age")) {
                misconfiguredHeaders.push("HSTS missing max-age");
            }
        }

        // -------- CLICKJACKING CHECK --------
        if (!headers["x-frame-options"] && !headers["content-security-policy"]) {
            vulnerabilities.push("Possible Clickjacking vulnerability");
        }

        // -------- INFORMATION DISCLOSURE --------
        if (headers["server"]) {
            infoDisclosure.push("Server header reveals technology: " + headers["server"]);
        }

        if (headers["x-powered-by"]) {
            infoDisclosure.push("X-Powered-By reveals backend: " + headers["x-powered-by"]);
        }

        // -------- COOKIE SECURITY --------
        const cookies = headers["set-cookie"];

        if (cookies) {

            cookies.forEach(cookie => {

                const lower = cookie.toLowerCase();

                if (!lower.includes("secure"))
                    cookieIssues.push("Cookie missing Secure flag");

                if (!lower.includes("httponly"))
                    cookieIssues.push("Cookie missing HttpOnly flag");

                if (!lower.includes("samesite"))
                    cookieIssues.push("Cookie missing SameSite attribute");
            });
        }

        return {
            target: url,
            status: response.status,
            missingHeaders,
            misconfiguredHeaders,
            cookieIssues,
            infoDisclosure,
            vulnerabilities
        };

    } catch (err) {

        return {
            target: url,
            error: "Website not reachable"
        };
    }
}

module.exports = scanHeaders;