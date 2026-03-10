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