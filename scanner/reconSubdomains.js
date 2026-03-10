const axios = require("axios");
const dns = require("dns").promises;

const wordlist = [
"api","dev","test","stage","staging",
"admin","mail","cdn","beta","app",
"portal","dashboard","secure"
];

async function reconSubdomains(domain) {
    const found = [];

    for (const sub of wordlist) {
        const hostname = sub + "." + domain;

        try {
            await dns.resolve4(hostname);
        } catch {
            continue;
        }

        const target = "https://" + hostname;
        try {
            const res = await axios.get(target, {
                timeout: 5000,
                validateStatus: () => true,
                maxRedirects: 3,
            });

            if (res.status < 400) {
                found.push(target);
            }
        } catch {
            try {
                const res = await axios.get("http://" + hostname, {
                    timeout: 5000,
                    validateStatus: () => true,
                    maxRedirects: 3,
                });
                if (res.status < 400) {
                    found.push("http://" + hostname);
                }
            } catch {}
        }
    }

    return found;
}

module.exports = reconSubdomains;