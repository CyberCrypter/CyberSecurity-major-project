const axios = require("axios");
const cheerio = require("cheerio");

async function findJSEndpoints(url) {

    let endpoints = new Set();
    let fullUrls = new Set();
    let graphql = new Set();
    let secrets = new Set();

    try {

        const res = await axios.get(url, {
            timeout: 8000,
            validateStatus: () => true,
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*"
            }
        });

        if (res.status >= 400 || typeof res.data !== "string") {
            return {
                target: url,
                endpoints: [],
                urls: [],
                graphql: [],
                secrets: []
            };
        }

        const $ = cheerio.load(res.data);

        let scripts = [];

        $("script").each((i, el) => {

            let src = $(el).attr("src");

            if (src) scripts.push(src);

        });

        // -------- helper function to scan JS --------

        async function scanJS(script) {

            let jsURL;

            try {
                jsURL = new URL(script, url).toString();
            } catch {
                return;
            }

            // ignore common static libraries
            if (
                jsURL.includes("jquery") ||
                jsURL.includes("bootstrap") ||
                jsURL.includes("analytics") ||
                jsURL.includes("gtag")
            ) {
                return;
            }

            try {

                const js = await axios.get(jsURL, {
                    timeout: 8000,
                    validateStatus: () => true,
                    headers: {
                        "User-Agent": "Mozilla/5.0"
                    }
                });

                if (js.status >= 400) return;

                const jsBody = typeof js.data === "string"
                    ? js.data
                    : JSON.stringify(js.data);

                // limit JS file size
                if (jsBody.length > 500000) return;

                // -------- endpoint detection --------

                const endpointRegex = /(\/api\/[a-zA-Z0-9_\-\/]*)|(\/v[0-9]+\/[a-zA-Z0-9_\-\/]*)|(\/auth\/[a-zA-Z0-9_\-\/]*)/g;

                let matches = jsBody.match(endpointRegex);

                if (matches) {
                    matches.forEach(m => endpoints.add(m));
                }

                // -------- full URL detection --------

                let urlMatches = jsBody.match(/https?:\/\/[a-zA-Z0-9\-._~:/?#@!$&'()*+,;=%]+/g);

                if (urlMatches) {
                    urlMatches.forEach(u => fullUrls.add(u));
                }

                // -------- graphql detection --------

                let gql = jsBody.match(/\/graphql[a-zA-Z0-9\/_-]*/g);

                if (gql) {
                    gql.forEach(g => graphql.add(g));
                }

                // -------- secret detection --------

                let secretMatches = jsBody.match(/(api[_-]?key|token|secret)[\"']?\s*[:=]\s*[\"'][^\"']+/gi);

                if (secretMatches) {
                    secretMatches.forEach(s => secrets.add(s));
                }

                // -------- interesting endpoints --------

                const interesting = ["admin", "internal", "debug", "private"];

                if (matches) {
                    matches.forEach(m => {
                        if (interesting.some(k => m.toLowerCase().includes(k))) {
                            endpoints.add(m + " (interesting)");
                        }
                    });
                }

            } catch (err) { }
        }

        // -------- run JS scanning in parallel --------

        const tasks = scripts.map(script => scanJS(script));

        await Promise.all(tasks);

    } catch (err) { }

    return {
        target: url,
        endpoints: [...endpoints],
        urls: [...fullUrls],
        graphql: [...graphql],
        secrets: [...secrets]
    };

}

module.exports = findJSEndpoints;