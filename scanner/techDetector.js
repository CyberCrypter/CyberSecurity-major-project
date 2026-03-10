const axios = require("axios");

async function detectTech(url) {

    let tech = new Set();

    try {

        const res = await axios.get(url, {
            timeout: 8000,
            validateStatus: () => true,
            headers: {
                "User-Agent": "Mozilla/5.0"
            }
        });

        if (res.status >= 400) {
            return {
                url,
                technologies: []
            };
        }

        const headers = res.headers;

        const html = typeof res.data === "string"
            ? res.data.toLowerCase()
            : JSON.stringify(res.data).toLowerCase();

        // ---------- HEADER DETECTION ----------

        if (headers["x-powered-by"])
            tech.add(headers["x-powered-by"]);

        if (headers["server"])
            tech.add("Server: " + headers["server"]);

        // ---------- CMS DETECTION ----------

        if (html.includes("wp-content"))
            tech.add("WordPress");

        if (html.includes("drupal"))
            tech.add("Drupal");

        if (html.includes("joomla"))
            tech.add("Joomla");

        if (html.includes("shopify"))
            tech.add("Shopify");

        if (html.includes("magento"))
            tech.add("Magento");

        // ---------- JAVASCRIPT FRAMEWORKS ----------

        if (html.includes("react"))
            tech.add("React");

        if (html.includes("react-dom"))
            tech.add("React");

        if (html.includes("angular"))
            tech.add("Angular");

        if (html.includes("vue"))
            tech.add("Vue.js");

        if (html.includes("__next"))
            tech.add("Next.js");

        if (html.includes("__nuxt"))
            tech.add("Nuxt.js");

        if (html.includes("jquery"))
            tech.add("jQuery");

        if (html.includes("bootstrap"))
            tech.add("Bootstrap");

        // ---------- BACKEND LANGUAGE HINTS ----------

        if (url.includes(".php"))
            tech.add("PHP");

        if (url.includes(".jsp"))
            tech.add("Java (JSP)");

        if (url.includes(".asp"))
            tech.add("ASP.NET");

        // ---------- ANALYTICS DETECTION ----------

        if (html.includes("google-analytics") || html.includes("gtag"))
            tech.add("Google Analytics");

        if (html.includes("hotjar"))
            tech.add("Hotjar");

        if (html.includes("segment"))
            tech.add("Segment");

        // ---------- CDN / WAF DETECTION ----------

        const serverHeader = (headers["server"] || "").toLowerCase();

        if (serverHeader.includes("cloudflare"))
            tech.add("Cloudflare");

        if (serverHeader.includes("akamai"))
            tech.add("Akamai");

        if (serverHeader.includes("fastly"))
            tech.add("Fastly");

        // ---------- META GENERATOR DETECTION ----------

        const generator = html.match(/<meta name="generator" content="([^"]+)"/i);

        if (generator && generator[1]) {
            tech.add("Generator: " + generator[1]);
        }

    } catch (err) { }

    return {
        url,
        technologies: [...tech]
    };

}

module.exports = detectTech;