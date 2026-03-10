function analyze(results) {
    let report = [];
    let riskScore = 0;

    // Security Headers
    const headerVulns = results.headers?.vulnerabilities || [];
    if (headerVulns.length > 0) {
        report.push(`Missing ${headerVulns.length} security header(s) — increases exposure to XSS, clickjacking, and MIME sniffing attacks.`);
        riskScore += headerVulns.length * 5;
    }

    // XSS Detection
    const xss = results.xss || "";
    if (/possible|vulnerable|found/i.test(String(xss))) {
        report.push("CRITICAL: Cross-Site Scripting (XSS) vulnerability detected — attacker can inject malicious scripts.");
        riskScore += 25;
    }

    // SQL Injection
    const sql = results.sql || "";
    if (/possible|vulnerable|found/i.test(String(sql))) {
        report.push("CRITICAL: SQL Injection vulnerability detected — database data may be compromised.");
        riskScore += 25;
    }

    // Exposed Directories
    if ((results.directories || []).length > 0) {
        report.push(`${results.directories.length} exposed director(ies) found — sensitive files may be publicly accessible.`);
        riskScore += results.directories.length * 3;
    }

    // Admin Panels
    if ((results.adminPanels || []).length > 0) {
        report.push(`${results.adminPanels.length} admin panel(s) discovered — potential target for brute force attacks.`);
        riskScore += results.adminPanels.length * 8;
    }

    // Open Ports
    const ports = results.openPorts || results.ports || [];
    if (ports.length > 0) {
        const riskPorts = [21, 22, 23, 3306, 5432, 27017, 6379];
        const dangerousPorts = ports.filter(p => riskPorts.includes(Number(p)));
        if (dangerousPorts.length > 0) {
            report.push(`High-risk port(s) open: ${dangerousPorts.join(", ")} — services like SSH, FTP, or databases are exposed.`);
            riskScore += dangerousPorts.length * 10;
        }
        if (ports.length > 5) {
            report.push(`${ports.length} open ports detected — large attack surface.`);
            riskScore += 5;
        }
    }

    // Parameters
    if ((results.parameters || []).length > 3) {
        report.push(`${results.parameters.length} parameters discovered — possible injection or IDOR attack vectors.`);
        riskScore += 5;
    }

    // Secrets
    if ((results.jsSecrets || []).length > 0) {
        report.push(`CRITICAL: ${results.jsSecrets.length} secret(s) found in JS files — API keys, tokens, or credentials may be leaked.`);
        riskScore += results.jsSecrets.length * 15;
    }

    // Subdomains
    if ((results.subdomains || []).length > 0) {
        report.push(`${results.subdomains.length} subdomain(s) enumerated — may expose staging/internal services.`);
        riskScore += 2;
    }

    // Technologies
    const techs = results.technologies || [];
    if (techs.length > 0) {
        const outdatedPatterns = /wordpress|jquery\s*1\.|php\/5|apache\/2\.2|nginx\/1\.1[0-8]/i;
        const outdated = techs.filter(t => outdatedPatterns.test(t));
        if (outdated.length > 0) {
            report.push(`Potentially outdated technology detected: ${outdated.join(", ")} — check for known CVEs.`);
            riskScore += outdated.length * 8;
        }
    }

    // API Endpoints
    if ((results.apis || []).length > 0) {
        report.push(`${results.apis.length} API endpoint(s) found — test for authentication bypass and rate limiting.`);
        riskScore += 3;
    }

    // JWT Analysis
    const jwt = results.jwtAnalysis;
    if (jwt && jwt.valid) {
        if ((jwt.vulnerabilities || []).length > 0) {
            report.push(`CRITICAL: JWT vulnerabilities found — ${jwt.vulnerabilities.join("; ")}`);
            riskScore += jwt.vulnerabilities.length * 20;
        }
        if ((jwt.warnings || []).length > 0) {
            report.push(`JWT warnings: ${jwt.warnings.join("; ")}`);
            riskScore += jwt.warnings.length * 5;
        }
    }

    // Bruteforce
    const brute = results.bruteforce;
    if (brute && brute.weakCredentials && brute.weakCredentials.length > 0) {
        report.push(`CRITICAL: ${brute.weakCredentials.length} weak credential(s) found via brute force — immediate password change required.`);
        riskScore += brute.weakCredentials.length * 25;
    } else if (brute && brute.loginFormsFound && brute.loginFormsFound.length > 0) {
        report.push(`${brute.loginFormsFound.length} login form(s) detected — ensure rate limiting and account lockout are in place.`);
        riskScore += 3;
    }

    // Overall risk level
    const cappedScore = Math.min(riskScore, 100);
    let riskLevel = "LOW";
    if (cappedScore > 70) riskLevel = "CRITICAL";
    else if (cappedScore > 40) riskLevel = "HIGH";
    else if (cappedScore > 15) riskLevel = "MEDIUM";

    if (report.length === 0) {
        report.push("No significant vulnerabilities detected. Target appears well-configured.");
    }

    report.unshift(`Overall Risk Level: ${riskLevel} (Score: ${cappedScore}/100)`);

    return report;
}

module.exports = analyze;