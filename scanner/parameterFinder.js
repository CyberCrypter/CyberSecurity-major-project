const axios = require("axios");
const fs = require("fs");
const path = require("path");

// load parameter wordlist
const params = fs
    .readFileSync(path.join(__dirname, "./wordlists/params.txt"), "utf8")

    .split("\n")
    .map(p => p.trim())
    .filter(Boolean);

// payloads to test
const payloads = [
    "test",
    "1",
    "admin",
    "<script>alert(1)</script>",
    "../../etc/passwd"
];

// similarity helper
function getWords(html) {

    const text = html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase();

    return new Set(text.split(" ").filter(w => w.length > 2));
}

function isSimilar(body1, body2) {

    if (!body1 || !body2) return false;

    if (body1 === body2) return true;

    const words1 = getWords(body1);
    const words2 = getWords(body2);

    let intersection = 0;

    for (const w of words1) {
        if (words2.has(w)) intersection++;
    }

    const union = new Set([...words1, ...words2]).size;

    return intersection / union > 0.8;
}

// scan one parameter
async function testParam(url, param, baselineBody) {

    let findings = [];

    for (const payload of payloads) {

        try {

            const target = new URL(url);

            target.searchParams.set(param, payload);

            const res = await axios.get(target.toString(), {
                timeout: 8000,
                validateStatus: () => true
            });

            const body = typeof res.data === "string"
                ? res.data
                : JSON.stringify(res.data);

            // reflection detection
            if (body.includes(payload)) {
                findings.push({
                    param,
                    payload,
                    type: "reflection"
                });
            }

            // redirect detection
            if (res.status >= 300 && res.status < 400) {
                findings.push({
                    param,
                    payload,
                    type: "redirect"
                });
            }

            // error-based detection
            const errors = ["sql", "exception", "error", "stack"];

            if (errors.some(e => body.toLowerCase().includes(e))) {
                findings.push({
                    param,
                    payload,
                    type: "error_based_response"
                });
            }

            // JSON API detection
            if (res.headers["content-type"]?.includes("json")) {
                findings.push({
                    param,
                    payload,
                    type: "json_api"
                });
            }

            // body difference detection
            if (!isSimilar(body, baselineBody)) {
                findings.push({
                    param,
                    payload,
                    type: "response_difference"
                });
            }

            // rate limit delay
            await new Promise(r => setTimeout(r, 100));

        } catch { }

    }

    return findings;
}

async function findParams(url) {

    let baselineBody = "";

    try {

        const baseRes = await axios.get(url, {
            timeout: 8000,
            validateStatus: () => true
        });

        baselineBody = typeof baseRes.data === "string"
            ? baseRes.data
            : JSON.stringify(baseRes.data);

    } catch {
        return [];
    }

    // run tests in parallel
    const tasks = params.map(p => testParam(url, p, baselineBody));

    const results = await Promise.all(tasks);

    return results.flat();

}

module.exports = findParams;