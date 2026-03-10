const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

function toList(value) {
	return Array.isArray(value) ? value.join(", ") : String(value || "None");
}

function writeSection(doc, title, value) {
	doc.font("Helvetica-Bold").text(`${title}:`);
	doc.font("Helvetica").text(value || "None", { indent: 12 });
	doc.moveDown(0.5);
}

function writeListSection(doc, title, list) {
	const values = Array.isArray(list) ? list : [];
	if (values.length === 0) {
		writeSection(doc, title, "None");
		return;
	}

	doc.font("Helvetica-Bold").text(`${title}:`);
	values.forEach((item) => {
		doc.font("Helvetica").text(`- ${String(item)}`, { indent: 12 });
	});
	doc.moveDown(0.5);
}

function generateReport(data, fileName = "scan-report.pdf") {
	return new Promise((resolve, reject) => {
		const reportsDir = path.join(__dirname, "..", "reports");
		fs.mkdirSync(reportsDir, { recursive: true });

		const outputPath = path.join(reportsDir, fileName);
		const doc = new PDFDocument({ margin: 50 });
		const stream = fs.createWriteStream(outputPath);

		stream.on("finish", () => resolve(outputPath));
		stream.on("error", reject);
		doc.on("error", reject);

		doc.pipe(stream);

		doc.fontSize(20).text("Website Vulnerability Report");
		doc.moveDown();

		const entries = Array.isArray(data) ? data : [];
		if (entries.length === 0) {
			doc.fontSize(12).text("No scan data available.");
			doc.end();
			return;
		}

		entries.forEach((site, index) => {
			if (index > 0) {
				doc.addPage();
			}

			doc.fontSize(16).font("Helvetica-Bold").text(`Target: ${site.target || "Unknown"}`);
			doc.moveDown(0.5);
			doc.fontSize(11).font("Helvetica");

			const headerFindings =
				site.headers && Array.isArray(site.headers.vulnerabilities)
					? site.headers.vulnerabilities
					: [];

			writeSection(doc, "XSS Result", site.xss || "N/A");
			writeSection(doc, "SQL Result", site.sql || "N/A");
			writeListSection(doc, "Missing Security Headers", headerFindings);
			writeListSection(doc, "Open Ports", site.ports || site.openPorts);
			writeListSection(doc, "Admin Panels", site.adminPanels);
			writeListSection(doc, "Directories", site.directories);
			writeListSection(doc, "Discovered Parameters", site.parameters);
			writeListSection(doc, "Crawled Pages", site.pages);
			writeListSection(doc, "JS Endpoints", site.jsEndpoints);
			writeListSection(doc, "API Endpoints", site.apis);
			writeListSection(doc, "Technologies", site.technologies);
			writeListSection(doc, "Subdomains", site.subdomains);
			writeListSection(doc, "Secrets Found", site.jsSecrets);

			// JWT Analysis
			const jwt = site.jwtAnalysis;
			if (jwt) {
				doc.font("Helvetica-Bold").text("JWT Analysis:");
				if (jwt.valid) {
					doc.font("Helvetica").text(`  Algorithm: ${jwt.algorithm || "N/A"}`, { indent: 12 });
					doc.font("Helvetica").text(`  Tokens Found: ${jwt.tokensFound || 0}`, { indent: 12 });
					if (jwt.vulnerabilities && jwt.vulnerabilities.length > 0) {
						doc.font("Helvetica").text("  Vulnerabilities:", { indent: 12 });
						jwt.vulnerabilities.forEach((v) => {
							doc.font("Helvetica").text(`    - ${v}`, { indent: 20 });
						});
					}
					if (jwt.warnings && jwt.warnings.length > 0) {
						doc.font("Helvetica").text("  Warnings:", { indent: 12 });
						jwt.warnings.forEach((w) => {
							doc.font("Helvetica").text(`    - ${w}`, { indent: 20 });
						});
					}
					if (jwt.attackSimulation && jwt.attackSimulation.type) {
						doc.font("Helvetica").text(`  Attack Simulation: ${jwt.attackSimulation.type}`, { indent: 12 });
						doc.font("Helvetica").text(`    ${jwt.attackSimulation.description || ""}`, { indent: 20 });
					}
				} else {
					doc.font("Helvetica").text(`  ${jwt.message || jwt.error || "No JWT tokens detected"}`, { indent: 12 });
				}
				doc.moveDown(0.5);
			}

			// Bruteforce Results
			const brute = site.bruteforce;
			if (brute) {
				doc.font("Helvetica-Bold").text("Brute Force Analysis:");
				doc.font("Helvetica").text(`  Summary: ${brute.summary || "N/A"}`, { indent: 12 });
				doc.font("Helvetica").text(`  Login Forms Found: ${(brute.loginFormsFound || []).length}`, { indent: 12 });
				doc.font("Helvetica").text(`  Endpoints Tested: ${(brute.testedEndpoints || []).length}`, { indent: 12 });
				doc.font("Helvetica").text(`  Total Attempts: ${brute.attempts || 0}`, { indent: 12 });
				if (brute.weakCredentials && brute.weakCredentials.length > 0) {
					doc.font("Helvetica").text("  Weak Credentials Found:", { indent: 12 });
					brute.weakCredentials.forEach((cred) => {
						doc.font("Helvetica").text(`    - ${cred.username}:${cred.password} at ${cred.endpoint}`, { indent: 20 });
					});
				}
				doc.moveDown(0.5);
			}

			writeListSection(doc, "AI Analysis", site.aiAnalysis);

			if (index < entries.length - 1) {
				doc.moveTo(50, doc.y).lineTo(550, doc.y).strokeColor("#cccccc").stroke();
				doc.moveDown();
			}
		});

		doc.end();
	});
}

module.exports = generateReport;