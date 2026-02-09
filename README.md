# logic-bench: Business Logic Vulnerability Benchmark

This repository contains a collection of micro-applications written in Python (Flask), Go, Node.js and Java. Each application is designed to simulate a realistic enterprise service containing intentional, high-severity business logic vulnerabilities.

These flaws are often missed by traditional SAST/DAST tools because they require understanding the *intent* of the code rather than just its syntax.

## Benchmark Vulnerability Summary

### 1. BadRewards (rewards.py)

**Theme:** Enterprise Logic Flaws

* **Privilege Escalation via Auth Fallthrough:** The 'admin_reset' function checks if a user is an admin and logs a warning if they aren't, but missing a 'return' statement allows execution to proceed to the database reset logic regardless of permissions.

* **Logical Inversion (Infinite Money):** The 'transfer_points' endpoint casts the amount to an integer but fails to check for positivity. Sending a negative amount increases the sender's balance ('balance - (-amount)') and decreases the recipient's.

* **Mass Assignment:** The 'update_settings' endpoint iterates over provided JSON keys to construct the SQL update. An attacker can inject fields like '"is_admin": 1' or '"balance": 99999' to modify protected columns.

* **SQL Injection via Column Names:** The 'update_settings' endpoint uses string formatting (f"{col} = ?") to build the SET clause. An attacker can inject arbitrary SQL (e.g., "balance = 0 --") to comment out the WHERE clause, affecting all users.

### 2. FlashSale (flashSale.py)

**Theme:** Concurrency & State Machines

* **State Machine Bypass:** The 'ship_order' endpoint checks if an order is already shipped or cancelled, but fails to verify if it is 'PAID'. An attacker can create an order and immediately ship it, bypassing the payment step.

* **Race Condition (TOCTOU):** The 'redeem_coupon' endpoint checks if a coupon is valid, waits (simulating latency), and then marks it used. Parallel requests sent during this window can reuse a single-use coupon multiple times.

* **Predictable Cryptography:** The 'recover_password' endpoint seeds the random number generator with 'int(time.time())'. An attacker can predict the 6-digit recovery token by synchronizing their local clock with the server's time.

### 3. SecureVault (secureVault.py)

**Theme:** Cryptography & Injection

* **JWT Algorithm Confusion:** The 'verify_token' function trusts the 'alg' header. If an attacker changes 'RS256' to 'HS256', the server uses its known Public Key as the HMAC shared secret, allowing the attacker to forge valid tokens.

* **Blind SQL Injection (ORDER BY):** The 'list_secrets' endpoint inserts the 'sort' parameter directly into the SQL query string. Since 'ORDER BY' cannot be parameterized in standard drivers, this allows blind injection.

* **Weak PRNG for Secrets:** The 'generate_backup_codes' endpoint uses 'random.randint' (Mersenne Twister), which is not cryptographically secure, to generate MFA backup codes.

### 4. PyReport (pyReport.py)

**Theme:** Language-Specific Deserialization & Injection

* **Insecure Deserialization (Pickle):** The 'get_preferences' function decodes a cookie and passes it directly to 'pickle.loads'. An attacker can craft a malicious pickle object to execute arbitrary code (RCE) on the server.

* **Server-Side Template Injection (SSTI):** The 'preview_report' endpoint inserts user input ('custom_title') directly into an f-string that is then processed by 'render_template_string'. This allows attackers to access the 'config' object or execute code via Jinja2 templates.

* **Zip Slip (Arbitrary File Overwrite):** The 'upload_dataset' endpoint uses 'zipfile.extractall' without validating the filenames inside the archive. A malicious zip containing paths like '../../script.py' can overwrite server files.

### 5. GoLedger (goLedger.go)

**Theme:** Concurrency & IDOR

* **Race Condition (Double Spend):** The TransferHandler reads the user's balance, waits (simulating latency), and then updates the balance. Because it lacks database transactions or row-level locking, concurrent requests can pass the balance check simultaneously, allowing users to spend more money than they own.

* **Infinite Refund Logic:** The RefundTransaction endpoint verifies the requester owns the transaction but fails to check if the transaction status is already 'REFUNDED'. An attacker can replay the request to drain the recipient's account.

* **Insecure Direct Object Reference (IDOR):** The GetStatement endpoint accepts an account_id query parameter and returns transactions for that ID without verifying it matches the authenticated user's ID, allowing data leakage.

* **Atomicity Failure (Data Destruction):** The TransferHandler updates the sender and recipient balances in two separate, non-transactional database calls. A failure after the first update results in money being deducted from the sender but not credited to the recipient.

### 6. GoChain (goChain.go)

**Theme:** Go Language Quirks & Crypto Logic

* **Variable Shadowing Auth Bypass:** In HandleProposeBlock, the authentication logic uses := inside an else block, creating a new local accessLevel variable. The outer accessLevel variable (defaulting to 0/Admin) remains unchanged. This grants Admin privileges to any user who provides an API key, regardless of its validity.

* **Typed Nil Interface Bypass:** The code retrieves a validator pointer which may be nil and stores it in an interface. The check if validator != nil evaluates to true for a typed nil. The subsequent method call validator.ValidateBlock executes on the nil receiver, which logic defaults to returning true, allowing signature verification bypass for non-existent validators.

* **Merkle Tree Second Preimage:** The MerkleRoot calculation concatenates child hashes (Hash(A) + Hash(B)) without domain separation/prefixes. An attacker can create a fake leaf node that mimics the concatenation of two internal nodes, allowing the forgery of Merkle inclusion proofs.

* **Broken Block Integrity:** The calculateHash function only hashes metadata (Index, Timestamp, PrevHash) and ignores the transactions list. This renders the Merkle Tree useless, as transactions can be tampered with without invalidating the block hash.

### 7. SSO Portal (sso_portal.py)

**Theme:** Identity Protocols & Side Channels

* **JWT 'None' Algorithm Bypass:** The 'validate_token' endpoint explicitly checks for the 'none' algorithm and enforces that the signature is empty. This logic validates the structure of an insecure token rather than rejecting the insecure algorithm itself, allowing attackers to forge valid tokens for any user by simply removing the signature.

* **XML External Entity (XXE) Injection:** The 'saml_consume' endpoint configures the 'lxml' parser with 'resolve_entities=True' when processing SAML responses. This allows an attacker to inject a malicious DOCTYPE defining external entities (e.g., file:///etc/passwd), which the parser resolves and returns in the API response.

* **Timing Side-Channel Attack:** The 'get_metrics' endpoint attempts to verify an API key using a manual loop with an early-exit ('break') optimization on mismatch. This creates a measurable timing difference depending on how many characters are correct, allowing an attacker to recover the secret key character-by-character.

### 8. Fintech API (fintech_api.js)

**Theme:** JavaScript Runtime & Regex

* **Prototype Pollution:** The 'mergeObjects' utility performs a deep merge of user-supplied data without filtering special keys like __proto__. An attacker can inject properties into Object.prototype, globally modifying the behavior of all objects in the application (e.g., setting isAdmin to true for everyone).

* **Crypto Type Confusion:** The 'verifySignature' function uses Buffer.from() on user input before passing it to timingSafeEqual. If an attacker supplies the signature as a non-string type (like an array of integers), they can manipulate the buffer construction or trigger unexpected comparison behavior, potentially bypassing HMAC verification.

* **ReDoS (Regular Expression Denial of Service):** The 'validate_email' endpoint uses a complex regex with nested quantifiers (([a-z]+)*) to validate internal email formats. A crafted input string (long alphanumeric sequence with no match) forces the regex engine into catastrophic backtracking, blocking the Node.js event loop and freezing the server.

### 9. Inventory Service (InventoryService.java)

**Theme:** Java Spring Framework & XML

* **SpEL Injection (Remote Code Execution):** The 'searchProducts' endpoint uses a StandardEvaluationContext to limit the scope of user-provided expressions. However, it fails to disable the use of Type references (T(...)). This allows attackers to instantiate arbitrary Java classes (like java.lang.Runtime) and execute system commands.

* **XML External Entity (XXE):** The 'importConfig' endpoint enables "secure-processing" and validation on the DocumentBuilderFactory. While this prevents some DoS attacks, it does not explicitly disable DOCTYPE declarations. An attacker can use this to read local files or perform Server-Side Request Forgery (SSRF) via external entities.

* **Transactional Race Condition:** The 'reserveStock' endpoint relies on the default @Transactional isolation (READ_COMMITTED) to manage inventory. Without explicit Pessimistic (FOR UPDATE) or Optimistic locking, concurrent requests can read the same stock level simultaneously, leading to "lost updates" and overselling of inventory.
