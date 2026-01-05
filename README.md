# logic-bench: Business Logic Vulnerability Benchmark

This repository contains a collection of micro-applications written in Python (Flask) and Go. Each application is designed to simulate a realistic enterprise service containing intentional, high-severity business logic vulnerabilities.

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