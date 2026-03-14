# Web-Analyzer

A Node.js based web vulnerability assessment tool with a modern browser dashboard.

Web-Analyzer scans one or many targets for common web security weaknesses, aggregates findings, calculates risk insights, and generates a PDF report.

## Important Notice

This project is for authorized security testing and educational use only.

Only scan systems you own or have explicit written permission to test.
Unauthorized testing may be illegal.

## Features

- Scan a single target URL or multiple targets in one run
- Security header checks
- Admin panel discovery
- Directory and common path discovery
- Reflected and simple parameterized XSS checks
- Basic SQL injection detection (error, timing, and response pattern based)
- Subdomain reconnaissance from a wordlist
- TCP port scan from a wordlist
- Query parameter discovery and payload reflection checks
- JavaScript endpoint extraction
- API endpoint discovery
- Technology fingerprinting from response headers and page content
- Secret discovery in JavaScript assets
- JWT extraction and security analysis
- Login endpoint discovery and weak credential brute force simulation
- AI-style risk summarization with score and severity
- PDF report export

## Tech Stack

- Node.js
- Express
- Axios
- Cheerio
- JSON Web Token
- PDFKit

## Project Structure

- public/: Frontend UI and scan dashboard
- scanner/: All scanner modules and wordlists
- scanner/wordlists/: Input dictionaries for paths, params, ports, and subdomains
- reports/: Generated PDF reports
- server.js: Main API server and scan orchestration
- vercel.json: Static deployment config for frontend-only deployment

## Scanner Modules

- scanner/headerScanner.js: Missing and weak security header checks
- scanner/adminFinder.js: Finds likely admin/login paths using baseline response comparison
- scanner/directoryScanner.js: Detects exposed directories and indexed paths
- scanner/xssScanner.js: Tests query parameters with multiple XSS payloads
- scanner/sqlScanner.js: Tests query parameters with SQLi payload sets
- scanner/reconSubdomains.js: Resolves subdomains and validates live hosts
- scanner/portScanner.js: Probes configured TCP ports
- scanner/parameterFinder.js: Discovers parameters and reflection/injection signals
- scanner/jsEndpointFinder.js: Extracts JS files and endpoints
- scanner/apiFinder.js: Finds common API paths from wordlist and heuristics
- scanner/techDetector.js: Detects technologies from HTML and headers
- scanner/secretFinder.js: Scans JS for keys, tokens, credentials, and secrets
- scanner/jwtScanner.js: Decodes and reviews JWT risks and warnings
- scanner/bruteforce.js: Finds login forms and tests weak credentials safely
- scanner/aiAnalyzer.js: Produces risk summary and score
- scanner/reportGenerator.js: Builds PDF report in reports/

## Requirements

- Node.js 18+ recommended
- npm

## Installation

1. Clone the repository.
2. Install dependencies:

```bash
npm install
```

## Running Locally

Start the API server:

```bash
node server.js
```

Server runs on:

- http://localhost:3000

Open the dashboard in your browser:

- http://localhost:3000

## API

### POST /scan

Starts a scan for one or many targets.

Request body supports either:

- Single URL:

```json
{
  "url": "https://example.com"
}
```

- Multiple URLs:

```json
{
  "targets": [
    "https://example.com",
    "https://example.org"
  ]
}
```

Response:

- Array of scan result objects, one per target

### GET /download-report

Downloads the latest generated PDF report.

- Output file name: vulnerability-report.pdf
- Source path: reports/scan-report.pdf

## Report Output

After each scan, a PDF report is generated containing findings such as:

- Risk summary and AI analysis
- Header findings
- XSS and SQL observations
- Admin panels, directories, and parameters
- Open ports and subdomains
- JS endpoints, APIs, technologies
- Secrets and JWT review
- Brute force results

## Notes and Limitations

- This is a heuristic scanner, not a replacement for a full manual penetration test.
- Network conditions, WAF behavior, and rate limits can affect results.
- Some modules use request timeouts and fallback behavior to keep scans responsive.
- False positives and false negatives are possible.

## Deployment

Current vercel.json is configured for static frontend deployment from public/.

If you need backend API endpoints in production, deploy server.js on a Node hosting platform (for example, Render, Railway, Fly.io, VPS, or container platform) and point the frontend to that API.

## Future Improvements

- Add npm scripts for start and dev modes
- Add authentication for scan API
- Add persistent scan history (database)
- Add CI checks and tests
- Improve signature quality and reduce false positives

## License

ISC

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you want to change.
