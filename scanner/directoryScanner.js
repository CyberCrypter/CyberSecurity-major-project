const axios = require("axios");
const fs = require("fs");
const path = require("path");

// load directories from wordlist
const directories = fs
  .readFileSync(path.join(__dirname, "./wordlists/directories.txt"), "utf8")

  .split("\n")
  .map(d => d.trim())
  .filter(Boolean);

// detect directory listing
function isDirectoryListing(body) {
    const lower = body.toLowerCase();

    return (
        lower.includes("index of /") ||
        lower.includes("parent directory") ||
        lower.includes("directory listing")
    );
}

// detect error pages
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

// text similarity check
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

// baseline response
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

// scan one directory
async function checkDirectory(url, dir, baseline, notFoundBaseline) {

    try {

        const target = url.replace(/\/+$/, "") + dir;

        const res = await axios.get(target, {
            timeout: 8000,
            validateStatus: () => true,
            maxRedirects: 0,
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*"
            }
        });

        const body =
            typeof res.data === "string"
                ? res.data
                : JSON.stringify(res.data);

        const contentType = (res.headers["content-type"] || "").toLowerCase();

        // ignore static resources
        if (
            contentType.includes("image") ||
            contentType.includes("font") ||
            contentType.includes("video")
        ) {
            return null;
        }

        // forbidden directory
        if (res.status === 403) {
            return { url: target, status: res.status, type: "forbidden directory" };
        }

        // interesting status codes
        if ([401, 405, 500].includes(res.status)) {
            return { url: target, status: res.status, type: "possible directory" };
        }

        if (res.status !== 200) return null;

        if (body.length < 50) return null;

        if (looksLikeErrorPage(body)) return null;

        if (isSimilar(body, baseline)) return null;

        if (isSimilar(body, notFoundBaseline)) return null;

        // directory listing detection
        if (isDirectoryListing(body)) {
            return { url: target, status: res.status, type: "directory listing" };
        }

        // sensitive directory detection
        const sensitive = [".env", ".git", "backup", "database", "config"];

        if (sensitive.some(k => target.includes(k))) {
            return { url: target, status: res.status, type: "sensitive directory" };
        }

        // backup files
        if (target.match(/\.(zip|sql|bak|tar|gz)$/)) {
            return { url: target, status: res.status, type: "backup file" };
        }

        // rate limit delay
        await new Promise(r => setTimeout(r, 100));

        return { url: target, status: res.status, type: "directory" };

    } catch {
        return null;
    }
}

// main scan function
async function scanDirectories(url) {

    const baseline = await getBaselineBody(url);

    const notFoundBaseline = await getBaselineBody(
        url + "/thispagedoesnotexist_" + Date.now()
    );

    const tasks = directories.map(dir =>
        checkDirectory(url, dir, baseline, notFoundBaseline)
    );

    const results = await Promise.all(tasks);

    return results.filter(Boolean);
}

module.exports = scanDirectories;