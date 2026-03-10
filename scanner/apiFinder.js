const axios = require("axios");

const apiPaths = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/login",
    "/api/users",
    "/api/health",
    "/api/status",
    "/graphql",
    "/rest",
    "/v1",
    "/v2",
    "/swagger",
    "/api-docs",
    "/openapi.json",
];

function getWords(html) {
    const text = html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase();
    return new Set(text.split(" ").filter((w) => w.length > 2));
}

function isSimilar(body1, body2) {
    if (!body1 || !body2) return false;
    if (body1 === body2) return true;

    const words1 = getWords(body1);
    const words2 = getWords(body2);

    if (words1.size === 0 && words2.size === 0) return true;
    if (words1.size === 0 || words2.size === 0) return false;

    let intersection = 0;
    for (const w of words1) {
        if (words2.has(w)) intersection++;
    }
    const union = new Set([...words1, ...words2]).size;
    return intersection / union > 0.8;
}

function looksLikeErrorPage(body) {
    const lower = body.toLowerCase();
    const titleMatch = lower.match(/<title[^>]*>([\s\S]*?)<\/title>/);
    const title = titleMatch ? titleMatch[1].trim() : "";
    const errorTerms = ["not found", "404", "page cannot", "does not exist", "unavailable", "error 404"];
    return errorTerms.some((t) => title.includes(t));
}

async function getBaselineBody(url) {
    try {
        const res = await axios.get(url, { timeout: 8000, validateStatus: () => true });
        return typeof res.data === "string" ? res.data : JSON.stringify(res.data);
    } catch {
        return "";
    }
}

async function findAPIs(url) {
    const found = [];
    const baseline = await getBaselineBody(url);
    const notFoundBaseline = await getBaselineBody(url + "/thispagedoesnotexist_" + Date.now());

    for (const p of apiPaths) {
        try {
            const target = url.replace(/\/+$/, "") + p;
            const res = await axios.get(target, {
                timeout: 8000,
                validateStatus: () => true,
                maxRedirects: 0,
            });

            if (res.status >= 300 && res.status < 400) continue;

            // 403 = API endpoint exists but is protected
            if (res.status === 403) {
                found.push(target + " (403 Forbidden)");
                continue;
            }

            if (res.status !== 200) continue;

            const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
            if (body.length < 2) continue;

            // JSON/API responses are inherently different from HTML pages — trust them
            const contentType = (res.headers["content-type"] || "").toLowerCase();
            if (contentType.includes("json") || contentType.includes("xml")) {
                found.push(target);
                continue;
            }

            if (body.length < 50) continue;
            if (looksLikeErrorPage(body)) continue;
            if (isSimilar(body, notFoundBaseline)) continue;
            if (isSimilar(body, baseline)) continue;

            found.push(target);
        } catch {}
    }

    return found;
}

module.exports = findAPIs;