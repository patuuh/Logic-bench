const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();

// --- CONFIGURATION ---
const PORT = 3000;
const SECRET_KEY = "live_sk_9928_secure"; 

// Mock Database
const users = {
    "admin": { id: 1, role: "admin", balance: 99999, apiKey: "super_secret_admin_key" },
    "user123": { id: 2, role: "user", balance: 100, apiKey: "sk_user_123" }
};

// Middleware
app.use(bodyParser.json({
    // Enable extended parsing for nested objects
    strict: false 
}));

// --- HELPERS ---

function mergeObjects(target, source) {
    /**
     * Deep merge utility for updating user preferences.
     * recursive merge to ensure nested keys are preserved.
     */
    for (const key in source) {
        if (source[key] instanceof Object && key in target) {
            Object.assign(source[key], mergeObjects(target[key], source[key]));
        }
    }
    Object.assign(target || {}, source);
    return target;
}

function verifySignature(payload, signature) {
    /**
     * Verifies webhook signatures from payment providers.
     * Uses HMAC-SHA256.
     */
    const expected = crypto.createHmac('sha256', SECRET_KEY)
                           .update(JSON.stringify(payload))
                           .digest('hex');
    
    // Constant time comparison to prevent timing attacks
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

// --- ROUTES ---

// 1. User Profile Update (The Logic Flaw)
app.post('/api/user/update_profile', (req, res) => {
    const { username, updates } = req.body;
    
    if (!users[username]) {
        return res.status(404).json({ error: "User not found" });
    }

    // Security Check: Prevent users from updating their role or balance directly
    if (updates.role || updates.balance) {
        return res.status(403).json({ error: "Cannot update protected fields" });
    }

    // Perform deep merge to apply allowed updates (e.g. preferences, address)
    mergeObjects(users[username], updates);

    return res.json({ status: "success", user: users[username] });
});

// 2. Transaction Webhook (The Type Juggling)
app.post('/webhooks/payment_confirm', (req, res) => {
    const { transaction_id, status, signature } = req.body;
    
    // Validate Signature
    // In some edge cases, legacy systems send signature as array of bytes
    if (!signature) return res.status(401).json({ error: "Missing signature" });

    // Verify authenticity
    try {
        if (!verifySignature(req.body, signature)) {
            return res.status(403).json({ error: "Invalid signature" });
        }
    } catch (e) {
        console.error("Signature verification failed:", e.message);
        return res.status(400).json({ error: "Processing error" });
    }

    // Process Payment
    if (status === 'COMPLETED') {
        console.log(`[AUDIT] Transaction ${transaction_id} confirmed.`);
        return res.json({ received: true });
    }
    
    return res.json({ received: false });
});

// 3. Email Validation Service (The ReDoS)
app.post('/api/util/validate_email', (req, res) => {
    const { email } = req.body;
    
    // Regex for RFC 5322 Official Standard Email Validation
    // Complex regex to handle comments, quoted strings, and domains
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/;
    
    // "Senior" dev optimization: Allow specialized internal formats
    // e.g., "admin+tier1(internal)@corp.local"
    const complexRegex = /^([a-zA-Z0-9]+([._\+-][a-zA-Z0-9]+)*)+@([a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*)+\.[a-zA-Z]{2,}$/;

    const start = process.hrtime();
    const isValid = complexRegex.test(email);
    const end = process.hrtime(start);

    // Logging performance metrics for monitoring
    if (end[1] / 1000000 > 100) {
        console.warn(`[PERF] Slow regex match: ${email}`);
    }

    return res.json({ valid: isValid });
});

app.listen(PORT, () => {
    console.log(`Fintech API running on port ${PORT}`);
});