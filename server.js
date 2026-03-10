const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crawl = require("./scanner/crawler");
const scanHeaders = require("./scanner/headerScanner");
const findAdmin = require("./scanner/adminFinder");
const scanXSS = require("./scanner/xssScanner");
const scanDirectories = require("./scanner/directoryScanner");
const scanSQL = require("./scanner/sqlScanner");
const scanSubdomains = require("./scanner/subdomainScanner");
const scanPorts = require("./scanner/portScanner");
const findParams = require("./scanner/parameterFinder");
const findJSEndpoints = require("./scanner/jsEndpointFinder");
const findAPIs = require("./scanner/apiFinder");
const detectTech = require("./scanner/techDetector");
const reconSubdomains = require("./scanner/reconSubdomains");
const findSecrets = require("./scanner/secretFinder");
const analyze = require("./scanner/aiAnalyzer");
const generateReport = require("./scanner/reportGenerator");


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

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

        const results = [];

        for (const url of targets) {
            const domain = url.replace("https://", "").replace("http://", "").split("/")[0];

            // Run ALL independent modules in parallel instead of sequentially
            const [
                headers, admin, xss, directories, sql,
                recon, ports, params, jsEndpoints,
                apis, technologies, pages
            ] = await Promise.all([
                safeRun(() => scanHeaders(url), { target: url, vulnerabilities: [] }, 15000),
                safeRun(() => findAdmin(url), [], 15000),
                safeRun(() => scanXSS(url), "Scan timeout", 15000),
                safeRun(() => scanDirectories(url), [], 15000),
                safeRun(() => scanSQL(url), "Scan timeout", 15000),
                safeRun(() => reconSubdomains(domain), [], 15000),
                safeRun(() => scanPorts(domain), [], 15000),
                safeRun(() => findParams(url), [], 15000),
                safeRun(() => findJSEndpoints(url), [], 15000),
                safeRun(() => findAPIs(url), [], 15000),
                safeRun(() => detectTech(url), [], 15000),
                safeRun(() => crawl(url), [], 20000),
            ]);

            // Secret finding depends on jsEndpoints, run after
            const secrets = [];
            const secretJobs = (jsEndpoints || []).map(js =>
                safeRun(() => findSecrets(js), [], 8000)
            );
            const secretResults = await Promise.all(secretJobs);
            for (const found of secretResults) secrets.push(...found);

            const aiReport = analyze({
                headers,
                directories,
                openPorts: ports,
                parameters: params,
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
                jsEndpoints,
                apis,
                technologies,
                subdomains: recon,
                jsSecrets: [...new Set(secrets)],
                aiAnalysis: aiReport,
            });
        }

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