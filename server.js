const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const crawl = require("./scanner/crawler");
const scanHeaders = require("./scanner/headerScanner");
const findAdmin = require("./scanner/adminFinder");
const scanXSS = require("./scanner/xssScanner");
const scanDirectories = require("./scanner/directoryScanner");
const scanSQL = require("./scanner/sqlScanner");
const scanPorts = require("./scanner/portScanner");
const findParams = require("./scanner/parameterFinder");
const findJSEndpoints = require("./scanner/jsEndpointFinder");
const findAPIs = require("./scanner/apiFinder");
const detectTech = require("./scanner/techDetector");
const reconSubdomains = require("./scanner/reconSubdomains");
const findSecrets = require("./scanner/secretFinder");
const scanJWT = require("./scanner/jwtScanner");
const bruteForceLogin = require("./scanner/bruteforce");
const analyze = require("./scanner/aiAnalyzer");
const generateReport = require("./scanner/reportGenerator");


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ─── Scan result cache ─────────────────────────────────────────────────────────
// Keyed by sorted target URLs joined with "|". TTL = 30 minutes.
// Ensures identical inputs always return identical outputs within the window.
const SCAN_CACHE = new Map();
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

function getCached(targets) {
    const key = [...targets].sort().join("|");
    const entry = SCAN_CACHE.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL_MS) {
        SCAN_CACHE.delete(key);
        return null;
    }
    return entry.data;
}

function setCache(targets, data) {
    const key = [...targets].sort().join("|");
    SCAN_CACHE.set(key, { ts: Date.now(), data });
}
// ───────────────────────────────────────────────────────────────────────────────

async function safeRun(taskFn, fallbackValue, timeoutMs = 20000) {
    try {
        const timeoutPromise = new Promise((resolve) => {
            setTimeout(() => resolve(fallbackValue), timeoutMs);
        });

        return await Promise.race([taskFn(), timeoutPromise]);
    } catch {
        return fallbackValue;
    }
}

app.post("/scan", async (req,res)=>{
    try {
        const rawTargets = Array.isArray(req.body.targets)
            ? req.body.targets
            : [req.body.url];

        const targets = rawTargets
            .filter(Boolean)
            .map((item) => String(item).trim())
            .filter(Boolean);

        if (targets.length === 0) {
            return res.status(400).json({ error: "Provide a valid URL in 'url' or 'targets'." });
        }

        // Return cached result if available (prevents score variance on re-scans)
        const forceRefresh = req.body.refresh === true || req.query.refresh === "true";
        if (!forceRefresh) {
            const cached = getCached(targets);
            if (cached) return res.json(cached);
        }

        const results = [];

        for (const url of targets) {
            const domain = url.replace("https://", "").replace("http://", "").split("/")[0];

            // Run ALL independent modules in parallel instead of sequentially
            const [
                headers, admin, xss, directories, sql,
                recon, ports, params, jsEndpoints,
                apis, technologies, pages, bruteforce
            ] = await Promise.all([
                safeRun(() => scanHeaders(url), { target: url, vulnerabilities: [] }, 20000),
                safeRun(() => findAdmin(url), [], 30000),
                safeRun(() => scanXSS(url), "Scan timeout", 25000),
                safeRun(() => scanDirectories(url), [], 30000),
                safeRun(() => scanSQL(url), "Scan timeout", 25000),
                safeRun(() => reconSubdomains(domain), [], 20000),
                safeRun(() => scanPorts(domain), [], 40000),
                safeRun(() => findParams(url), [], 20000),
                safeRun(() => findJSEndpoints(url), [], 20000),
                safeRun(() => findAPIs(url), [], 20000),
                safeRun(() => detectTech(url), [], 20000),
                safeRun(() => crawl(url), [], 30000),
                safeRun(() => bruteForceLogin(url), { loginFormsFound: [], testedEndpoints: [], weakCredentials: [], attempts: 0, summary: "Scan timeout" }, 40000),
            ]);

            // Normalize JS endpoint scanner output for compatibility.
            let jsEndpointsArray = [];
            let jsUrls = [];

            if (Array.isArray(jsEndpoints)) {
                jsEndpointsArray = jsEndpoints;
            } else if (jsEndpoints && typeof jsEndpoints === "object") {
                jsEndpointsArray = Array.isArray(jsEndpoints.endpoints) ? jsEndpoints.endpoints : [];
                jsUrls = Array.isArray(jsEndpoints.urls) ? jsEndpoints.urls : [];
            }

            // Secret finding depends on JS assets, run after endpoint scan.
            const secretTargets = jsUrls.length > 0
                ? jsUrls.filter((u) => /\.js(\?|$)/i.test(String(u)))
                : jsEndpointsArray;

            const secrets = [];
            const secretJobs = secretTargets.map((target) =>
                safeRun(() => findSecrets(target), [], 8000)
            );
            const secretResults = await Promise.all(secretJobs);
            for (const found of secretResults) secrets.push(...found);

            // JWT: Try to extract tokens from response headers/cookies
            let jwtAnalysis = null;
            try {
                const res = await axios.get(url, { timeout: 8000, validateStatus: () => true, maxRedirects: 3 });
                const allHeaders = JSON.stringify(res.headers || {});
                const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data || {});
                const combined = allHeaders + " " + body;

                const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
                const tokens = combined.match(jwtRegex) || [];

                if (tokens.length > 0) {
                    jwtAnalysis = scanJWT(tokens[0]);
                    jwtAnalysis.tokensFound = tokens.length;
                }
            } catch { }

            if (!jwtAnalysis) {
                jwtAnalysis = { valid: false, tokensFound: 0, warnings: [], vulnerabilities: [], message: "No JWT tokens detected" };
            }

            const aiReport = analyze({
                headers,
                directories,
                openPorts: ports,
                parameters: params,
                xss,
                sql,
                adminPanels: admin,
                jsSecrets: [...new Set(secrets)],
                subdomains: recon,
                technologies,
                apis,
                jwtAnalysis,
                bruteforce,
            });

            results.push({
                target: url,
                headers,
                adminPanels: admin,
                directories,
                sql,
                xss,
                ports,
                openPorts: ports,
                parameters: params,
                pages,
                jsEndpoints: jsEndpointsArray,
                apis,
                technologies,
                subdomains: recon,
                jsSecrets: [...new Set(secrets)],
                jwtAnalysis,
                bruteforce,
                aiAnalysis: aiReport,
            });
        }

        // Cache results so repeated scans of the same target return identical data
        setCache(targets, results);

        // Generate report synchronously so /download-report works right after scan
        await safeRun(() => generateReport(results), null, 10000);
        return res.json(results);
    } catch (err) {
        return res.status(500).json({ error: "Scan failed", details: err.message });
    }
})

app.get("/download-report", (req, res) => {
    const reportPath = path.join(__dirname, "reports", "scan-report.pdf");
    if (!fs.existsSync(reportPath)) {
        return res.status(404).json({ error: "No report available. Run a scan first." });
    }
    res.download(reportPath, "vulnerability-report.pdf");
});

app.listen(3000,()=>{
    console.log("Scanner running on port 3000");
})