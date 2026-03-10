const axios = require("axios");
const cheerio = require("cheerio");

async function crawl(url) {
    const visited = new Set();
    const toVisit = [url];
    const pages = [];
    const maxPages = 50;

    while (toVisit.length > 0 && pages.length < maxPages) {
        const current = toVisit.pop();
        if (visited.has(current)) continue;
        visited.add(current);

        try {
            const res = await axios.get(current, {
                timeout: 8000,
                validateStatus: () => true,
            });

            if (res.status !== 200) continue;

            // Only add verified pages (not the start URL itself)
            if (current !== url) {
                pages.push(current);
            }

            const $ = cheerio.load(res.data);

            $("a").each((i, link) => {
                let href = $(link).attr("href");
                if (!href) return;

                // Handle relative paths
                if (href.startsWith("/")) {
                    href = url.replace(/\/+$/, "") + href;
                }

                // Only follow links on the same domain
                if (href.startsWith(url) && !visited.has(href)) {
                    toVisit.push(href);
                }
            });
        } catch (err) {}
    }

    return pages;
}

module.exports = crawl;