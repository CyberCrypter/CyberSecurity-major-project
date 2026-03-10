const axios = require("axios");
const fs = require("fs");
const path = require("path");

// load API paths from wordlist
const apiPaths = fs
  .readFileSync(path.join(__dirname, "./wordlists/api-endpoints.txt"), "utf8")
  .split("\n")
  .map(p => p.trim())
  .filter(Boolean);

// ---------- helper functions ----------

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

    const errorTerms = [
        "not found",
        "404",
        "page cannot",
        "does not exist",
        "unavailable",
        "error 404"
    ];

    return errorTerms.some(t => title.includes(t));
}

async function getBaselineBody(url) {

    try {

        const res = await axios.get(url, {
            timeout: 8000,
            validateStatus: () => true
        });

        return typeof res.data === "string"
            ? res.data
            : JSON.stringify(res.data);

    } catch {
        return "";
    }
}

// ---------- API detection ----------

async function checkAPI(url, path, baseline, notFoundBaseline) {

    try {

        const target = url.replace(/\/+$/, "") + path;

        const res = await axios.get(target, {
            timeout: 8000,
            validateStatus: () => true,
            maxRedirects: 0,
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json"
            }
        });

        const body =
            typeof res.data === "string"
                ? res.data
                : JSON.stringify(res.data);

        const contentType = (res.headers["content-type"] || "").toLowerCase();

        // 403 means endpoint exists but protected
        if (res.status === 403) {
            return target + " (403 Forbidden)";
        }

        // JSON / XML APIs
        if (contentType.includes("json") || contentType.includes("xml")) {
            return target + " (API response)";
        }

        // detect JSON even if header wrong
        try {
            JSON.parse(body);
            return target + " (JSON API)";
        } catch {}

        // GraphQL detection
        if (path.includes("graphql")) {

            try {

                const gql = await axios.post(
                    target,
                    { query: "{ __typename }" },
                    {
                        timeout: 8000,
                        validateStatus: () => true
                    }
                );

                if (gql.status === 200) {
                    return target + " (GraphQL endpoint)";
                }

            } catch {}
        }

        // swagger / api docs detection
        if (
            body.includes("swagger") ||
            body.includes("openapi") ||
            body.includes("swagger-ui")
        ) {

            return target + " (API docs / swagger)";
        }

        if (res.status !== 200) return null;

        if (body.length < 50) return null;

        if (looksLikeErrorPage(body)) return null;

        if (isSimilar(body, baseline)) return null;

        if (isSimilar(body, notFoundBaseline)) return null;

        return target;

    } catch {
        return null;
    }
}

// ---------- main scanner ----------

async function findAPIs(url) {

    const baseline = await getBaselineBody(url);

    const notFoundBaseline = await getBaselineBody(
        url + "/thispagedoesnotexist_" + Date.now()
    );

    // run requests in parallel
    const tasks = apiPaths.map(path =>
        checkAPI(url, path, baseline, notFoundBaseline)
    );

    const results = await Promise.all(tasks);

    return results.filter(Boolean);
}

module.exports = findAPIs;