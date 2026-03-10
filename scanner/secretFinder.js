const axios = require("axios");

async function findSecrets(jsURL) {

    let secrets = [];
    let foundValues = new Set();

    try {

        const res = await axios.get(jsURL, {
            timeout: 8000,
            validateStatus: () => true,
            headers: {
                "User-Agent": "Mozilla/5.0"
            }
        });

        if (res.status >= 400) {
            return {
                file: jsURL,
                secrets: []
            };
        }

        let content = typeof res.data === "string"
            ? res.data
            : JSON.stringify(res.data);

        // prevent scanning huge files
        if (content.length > 1000000) {
            return {
                file: jsURL,
                secrets: []
            };
        }

        // secret patterns with type
        const patterns = [

            { type: "Google API Key", regex: /AIza[0-9A-Za-z-_]{35}/g },

            { type: "Stripe Secret Key", regex: /sk_live_[0-9a-zA-Z]{24}/g },

            { type: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g },

            { type: "GitHub Token", regex: /ghp_[0-9A-Za-z]{36}/g },

            { type: "Slack Token", regex: /xox[baprs]-[0-9A-Za-z-]+/g },

            { type: "JWT Token", regex: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g },

            { type: "Private Key", regex: /-----BEGIN PRIVATE KEY-----/g },

            { type: "API Key Variable", regex: /(api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']+["']/gi },

            { type: "Base64 Secret", regex: /[A-Za-z0-9+\/]{40,}={0,2}/g },

            { type: "Environment Variable", regex: /process\.env\.[A-Z0-9_]+/g }

        ];

        for (const pattern of patterns) {

            const matches = content.match(pattern.regex);

            if (matches) {

                for (const match of matches) {

                    if (foundValues.has(match)) continue;

                    foundValues.add(match);

                    // context extraction
                    const index = content.indexOf(match);

                    const context = content.slice(
                        Math.max(0, index - 40),
                        Math.min(content.length, index + 40)
                    );

                    secrets.push({
                        type: pattern.type,
                        value: match,
                        context
                    });

                }

            }

        }

    } catch (err) { }

    return {
        file: jsURL,
        secrets
    };

}

module.exports = findSecrets;