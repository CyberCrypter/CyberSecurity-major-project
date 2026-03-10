const axios = require("axios");
const cheerio = require("cheerio");

// normalize URLs to avoid duplicates
function normalizeUrl(u) {
    try {
        const parsed = new URL(u);

        parsed.hash = "";
        parsed.search = "";

        return parsed.toString().replace(/\/+$/, "");
    } catch {
        return null;
    }
}

// ignore static files
const ignoredExtensions = [
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico",
    ".pdf", ".zip", ".rar", ".tar", ".gz", ".mp4", ".mp3", ".woff", ".woff2"
];

// interesting keywords for security
const interestingKeywords = [
    "login", "admin", "dashboard", "api", "upload", "account", "reset", "auth"
];

async function crawl(url) {

    const visited = new Set();
    const pages = [];

    const maxPages = 50;
    const maxDepth = 3;
    const concurrency = 5;

    const baseHost = new URL(url).hostname;

    const queue = [{ url: normalizeUrl(url), depth: 0 }];

    async function crawlPage({ url: current, depth }) {

        if (!current) return;
        if (visited.has(current)) return;
        if (pages.length >= maxPages) return;
        if (depth > maxDepth) return;

        visited.add(current);

        try {

            const res = await axios.get(current, {
                timeout: 8000,
                validateStatus: () => true,
                maxRedirects: 3
            });

            if (res.status !== 200) return;

            if (current !== normalizeUrl(url)) {
                pages.push(current);
            }

            const $ = cheerio.load(res.data);

            $("a, link, script, iframe, form").each((i, el) => {

                let href =
                    $(el).attr("href") ||
                    $(el).attr("src") ||
                    $(el).attr("action");

                if (!href) return;

                // convert relative URL
                try {
                    href = new URL(href, current).toString();
                } catch {
                    return;
                }

                // normalize
                const normalized = normalizeUrl(href);
                if (!normalized) return;

                // prevent infinite loops
                if (normalized.split("?").length > 2) return;

                // ignore static files
                if (ignoredExtensions.some(ext => normalized.endsWith(ext))) return;

                // same domain only
                try {
                    const host = new URL(normalized).hostname;
                    if (host !== baseHost) return;
                } catch {
                    return;
                }

                // detect query parameters
                if (href.includes("?")) {
                    pages.push(href + " (parameter)");
                }

                // detect interesting pages
                if (interestingKeywords.some(k => normalized.toLowerCase().includes(k))) {
                    pages.push(normalized + " (interesting)");
                }

                if (!visited.has(normalized)) {
                    queue.push({
                        url: normalized,
                        depth: depth + 1
                    });
                }

            });

        } catch { }
    }

    while (queue.length > 0 && pages.length < maxPages) {

        const batch = queue.splice(0, concurrency);

        await Promise.all(
            batch.map(item => crawlPage(item))
        );
    }

    return [...new Set(pages)];
}

module.exports = crawl;