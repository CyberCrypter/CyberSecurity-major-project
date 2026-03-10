const axios = require("axios");

const params = [
"id",
"user",
"search",
"query",
"token",
"redirect"
];

async function findParams(url) {
    let discovered = [];
    let baselineBody = "";

    try {
        const baseRes = await axios.get(url, { timeout: 8000, validateStatus: () => true });
        baselineBody = typeof baseRes.data === "string" ? baseRes.data : JSON.stringify(baseRes.data);
    } catch {
        return discovered;
    }

    for (const p of params) {
        try {
            const target = new URL(url);
            target.searchParams.set(p, "test");

            const res = await axios.get(target.toString(), {
                timeout: 8000,
                validateStatus: () => true,
            });

            if (res.status !== 200) continue;

            const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
            if (body !== baselineBody) {
                discovered.push(p);
            }
        } catch {}
    }

    return discovered;
}

module.exports = findParams;