const net = require("net");
const fs = require("fs");
const path = require("path");

// load ports from wordlist
const ports = fs
    .readFileSync(path.join(__dirname, "./wordlists/ports.txt"), "utf8")

    .split("\n")
    .map(p => parseInt(p.trim()))
    .filter(Boolean);

// common service mapping
const services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    27017: "MongoDB"
};

async function scanPorts(host, timeout = 1000, concurrency = 50) {

    if (!host) {
        throw new Error("Host required");
    }

    let results = [];
    let queue = [...ports];

    async function scanSinglePort(port) {

        return new Promise((resolve) => {

            let banner = "";
            let status = "closed";

            const socket = new net.Socket();

            socket.setTimeout(timeout);

            socket.connect(port, host, () => {

                status = "open";

                socket.write("HEAD / HTTP/1.0\r\n\r\n");

            });

            socket.on("data", (data) => {

                banner = data.toString().slice(0, 100);

            });

            socket.on("timeout", () => {

                if (status !== "open") {
                    status = "filtered";
                }

                socket.destroy();
                resolve();

            });

            socket.on("error", () => {

                status = "closed";
                resolve();

            });

            socket.on("close", () => {

                if (status === "open") {

                    results.push({
                        port,
                        status,
                        service: services[port] || "unknown",
                        banner
                    });

                }

            });

        });

    }

    // worker system for concurrency
    let workers = [];

    for (let i = 0; i < concurrency; i++) {

        workers.push((async () => {

            while (queue.length) {

                const port = queue.shift();

                await scanSinglePort(port);

            }

        })());

    }

    await Promise.all(workers);

    return results;

}

module.exports = scanPorts;