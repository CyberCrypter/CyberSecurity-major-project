const axios = require("axios");
const dns = require("dns").promises;
const fs = require("fs");
const path = require("path");

// load wordlist
const wordlist = fs
    .readFileSync(path.join(__dirname, "./wordlists/subdomains.txt"), "utf8")
    .split("\n")
    .map(w => w.trim())
    .filter(Boolean);

// detect wildcard DNS
async function detectWildcard(domain) {

    const random = Math.random().toString(36).substring(7);

    try {
        await dns.resolve4(random + "." + domain);
        return true;
    } catch {
        return false;
    }

}

async function scanSubdomain(sub, domain, wildcard) {

    const hostname = sub + "." + domain;

    try {

        const addresses = await dns.resolve4(hostname);

        if (!addresses.length) return null;

        if (wildcard) {
            return null;
        }

    } catch {
        return null;
    }

    let result = {
        url: null,
        title: null,
        server: null,
        redirect: null,
        waf: null
    };

    // try https first
    let target = "https://" + hostname;

    try {

        const res = await axios.get(target, {
            timeout: 5000,
            validateStatus: () => true,
            maxRedirects: 3,
            headers: {
                "User-Agent": "Mozilla/5.0"
            }
        });

        if (res.status < 400) {

            result.url = target;

            // title extraction
            const match = typeof res.data === "string"
                ? res.data.match(/<title>(.*?)<\/title>/i)
                : null;

            if (match) {
                result.title = match[1];
            }

            // server detection
            result.server = res.headers.server || null;

            // redirect detection
            if (res.request?.res?.responseUrl && res.request.res.responseUrl !== target) {
                result.redirect = res.request.res.responseUrl;
            }

            // WAF detection
            const server = (res.headers.server || "").toLowerCase();

            if (server.includes("cloudflare")) result.waf = "Cloudflare";
            if (server.includes("akamai")) result.waf = "Akamai";
            if (server.includes("fastly")) result.waf = "Fastly";

            return result;

        }

    } catch {

        // fallback to http

        try {

            target = "http://" + hostname;

            const res = await axios.get(target, {
                timeout: 5000,
                validateStatus: () => true,
                maxRedirects: 3
            });

            if (res.status < 400) {

                result.url = target;

                const match = typeof res.data === "string"
                    ? res.data.match(/<title>(.*?)<\/title>/i)
                    : null;

                if (match) {
                    result.title = match[1];
                }

                result.server = res.headers.server || null;

                return result;

            }

        } catch { }

    }

    return null;

}

async function reconSubdomains(domain) {

    const wildcard = await detectWildcard(domain);

    let queue = [...wordlist];

    let results = [];

    const concurrency = 30;

    let workers = [];

    for (let i = 0; i < concurrency; i++) {

        workers.push((async () => {

            while (queue.length) {

                const sub = queue.shift();

                const res = await scanSubdomain(sub, domain, wildcard);

                if (res) {
                    results.push(res);
                }

                // rate limit
                await new Promise(r => setTimeout(r, 50));

            }

        })());

    }

    await Promise.all(workers);

    return results;

}

module.exports = reconSubdomains;