const jwt = require("jsonwebtoken");

function scanJWT(token, secret = null, publicKey = null) {

    try {

        // -------- STRUCTURE VALIDATION --------
        if (token.split(".").length !== 3) {
            return {
                valid: false,
                error: "Invalid JWT format"
            };
        }

        const decoded = jwt.decode(token, { complete: true });

        if (!decoded || !decoded.header || !decoded.payload) {
            return {
                valid: false,
                error: "Unable to decode JWT"
            };
        }

        const header = decoded.header;
        const payload = decoded.payload;

        let warnings = [];
        let vulnerabilities = [];
        let attackSimulation = {};

        // -------- ALG NONE CHECK --------
        if (header.alg && header.alg.toLowerCase() === "none") {
            vulnerabilities.push("JWT vulnerability: alg none allows signature bypass");
        }

        // -------- WEAK ALGORITHM CHECK --------
        const weakAlgos = ["hs256", "hs384", "hs512"];

        if (header.alg && weakAlgos.includes(header.alg.toLowerCase())) {
            warnings.push("JWT uses symmetric algorithm (possible brute force risk)");
        }

        // -------- EXPIRATION CHECK --------
        const now = Math.floor(Date.now() / 1000);

        if (payload.exp) {

            if (payload.exp < now) {
                warnings.push("JWT token expired");
            }

            if (payload.iat) {

                const lifetime = payload.exp - payload.iat;

                if (lifetime > 31536000) {
                    warnings.push("JWT expiration too long (>1 year)");
                }
            }

        } else {
            warnings.push("JWT has no expiration");
        }

        // -------- ISS / AUD CHECK --------
        if (!payload.iss) {
            warnings.push("JWT missing issuer (iss)");
        }

        if (!payload.aud) {
            warnings.push("JWT missing audience (aud)");
        }

        // -------- SENSITIVE DATA CHECK --------
        const sensitiveKeys = ["password", "secret", "apikey", "api_key", "token"];

        for (const key in payload) {
            if (sensitiveKeys.includes(key.toLowerCase())) {
                warnings.push("Sensitive data inside JWT payload: " + key);
            }
        }

        // -------- SIGNATURE VERIFICATION --------
        let signatureValid = null;

        if (secret) {

            try {
                jwt.verify(token, secret);
                signatureValid = true;
            } catch {
                signatureValid = false;
                warnings.push("JWT signature verification failed");
            }

        }

        // -------- JWT ALGORITHM CONFUSION DETECTION --------

        if (header.alg && header.alg.toLowerCase().startsWith("rs")) {

            warnings.push("JWT uses RSA algorithm - check for RS256 → HS256 confusion risk");

            // simulate attacker modifying token
            const forgedHeader = {
                ...header,
                alg: "HS256"
            };

            // attacker escalates privileges
            const forgedPayload = {
                ...payload,
                role: "admin"
            };

            try {

                const forgedToken = jwt.sign(
                    forgedPayload,
                    publicKey || "public_key_placeholder",
                    {
                        algorithm: "HS256"
                    }
                );

                attackSimulation = {
                    type: "Algorithm Confusion Attack",
                    description: "If server incorrectly treats public key as HMAC secret, this forged token may be accepted",
                    forgedToken
                };

            } catch { }

        }

        return {
            valid: true,
            algorithm: header.alg,
            header,
            payload,
            signatureValid,
            warnings,
            vulnerabilities,
            attackSimulation
        };

    } catch (err) {

        return {
            valid: false,
            error: "Invalid JWT"
        };
    }
}

module.exports = scanJWT;