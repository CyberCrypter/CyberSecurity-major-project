const axios = require("axios");
const fs = require("fs");
const path = require("path");


// load paths from wordlist
const paths = fs
    .readFileSync(path.join(__dirname, "./wordlists/admin-panels.txt"), "utf8")
    .split("\n")
    .map(p => p.trim())
    .filter(Boolean);

// detect login forms
function hasLoginForm(body) {
    const lower = body.toLowerCase();

    return (
        lower.includes('type="password"') ||
        lower.includes("name=\"password\"") ||
        lower.includes("login") ||
        lower.includes("signin") ||
        lower.includes("sign in")
    );
}

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

    const errorTerms = [
        "not found",
        "404",
        "page cannot",
        "does not exist",
        "unavailable",
        "error 404"
    ];

    return errorTerms.some((t) => title.includes(t));
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

// analyze each path
async function checkPath(url, p, baseline, notFoundBaseline) {

    try {

        const target = url.replace(/\/+$/, "") + p;

        const res = await axios.get(target, {
            timeout: 8000,
            validateStatus: () => true,
            maxRedirects: 0
        });

        // redirect detection
        if (res.status >= 300 && res.status < 400) {

            const location = (res.headers.location || "").toLowerCase();

            if (
                location.includes("login") ||
                location.includes("auth") ||
                location.includes("sign")
            ) {
                return target + " (redirects to login)";
            }

            return null;
        }

        // forbidden detection
        if (res.status === 403) {
            return target + " (403 Forbidden)";
        }

        if (res.status !== 200) return null;

        const body =
            typeof res.data === "string"
                ? res.data
                : JSON.stringify(res.data);

        if (body.length < 50) return null;

        if (looksLikeErrorPage(body)) return null;

        if (isSimilar(body, notFoundBaseline)) return null;

        if (isSimilar(body, baseline)) return null;

        // login form detection
        if (hasLoginForm(body)) {
            return target + " (login page detected)";
        }

        return target;

    } catch {
        return null;
    }
}

async function findAdmin(url) {

    const baseline = await getBaselineBody(url);

    const notFoundBaseline = await getBaselineBody(
        url + "/thispagedoesnotexist_" + Date.now()
    );

    // run all requests in parallel
    const tasks = paths.map(p =>
        checkPath(url, p, baseline, notFoundBaseline)
    );

    const results = await Promise.all(tasks);

    return results.filter(Boolean);
}

module.exports = findAdmin;