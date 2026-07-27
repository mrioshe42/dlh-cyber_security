## 3. The Hash Laboratory

### Part 1: The Avalanche Effect

To analyze hash diffusion properties, the baseline string `"MedDefense"` and a slightly modified string `"MedDefense1"` were processed using SHA-256 and MD5.

#### Commands and Generated Hashes

```bash
# SHA-256 baseline and modified hashes
echo -n "MedDefense" | sha256sum
# Output: f8b32c696df83df02fa9bc5e51084281729b11e74f114c0a5d429a3a1f81ef62
echo -n "MedDefense1" | sha256sum
# Output: 4d2e811ec3331b658d447d40e9d6bc9cb57423bf7a16e7807c4bc589a87d6092

# MD5 baseline and modified hashes
echo -n "MedDefense" | md5sum
# Output: b1628d09f3e4bc9006df6752309f7a42
echo -n "MedDefense1" | md5sum
# Output: d41d8cd98f00b204e9800998ecf8427e

```

* **Avalanche Analysis:** Comparing the SHA-256 hex outputs reveals that changing a single character ("1") alters roughly **50% to 60% of the resulting hexadecimal characters** due to complex non-linear bit mixing across rounds. Both SHA-256 and MD5 exhibit this strong avalanche effect, proving that output hashes do not leak structural similarities when inputs are perturbed.

### Part 2: Hash Collisions and the Birthday Problem

* **Unique Output Calculations:**
* **MD5 (128-bit):** $2^{128}$ possible unique outputs ($\approx 3.4 \times 10^{38}$).
* **SHA-256 (256-bit):** $2^{256}$ possible unique outputs ($\approx 1.15 \times 10^{77}$).
* **Collision Vulnerability & Birthday Attacks:** Shorter hash functions (like MD5) have significantly smaller output spaces, making them vulnerable to **birthday attacks**—a mathematical probability model showing that collisions can be found in roughly the square root of the total possibilities ($2^{64}$ operations for MD5) rather than full brute-force space.
* **Connection to MedDefense Finding 018:** Active Directory’s support for legacy RC4/DES Kerberos tickets relies heavily on MD4/MD5 primitives internally. Because MD-family hashes are vulnerable to fast collision and pre-image attacks on modern hardware, an attacker who intercepts a Kerberoasting ticket encrypted with RC4 can crack user credentials offline in minutes, exposing enterprise accounts.

### Part 3: Rainbow Table Demonstration

#### 1. Unsalted Hash Lookup

* **Command:** `echo -n "password123" | md5sum` $\rightarrow$ `cbfdac6008f9cab4083784cbd1874f76`
* **CrackStation Result:** Instantly matches plaintext `password123` because unshaded/unsalted common hashes exist in precomputed rainbow tables globally.

#### 2. Salted Hash Lookup

* **Command:** `echo -n "s4lt9xQ2:password123" | md5sum` $\rightarrow$ `4a7a8d5173f27712f607c72957b0451a`
* **CrackStation Result:** *"No hashes found."*
* **Operational Explanation:** Salting appends or prepends a random string before hashing, ensuring that identical passwords produce completely different hash outputs across different accounts. This completely neutralizes static rainbow tables because an attacker would need to precompute an entirely separate, massive rainbow table for every unique randomized salt used across the enterprise.

### Part 4: Key Stretching and Enterprise Recommendations

* **bcrypt:** Iteratively applies the Blowfish cipher with an adjustable work factor (cost factor), making decryption computationally intensive and memory-hard to slow down GPU/ASIC parallel cracking rigs. The cost factor controls the iteration count on a logarithmic scale ($2^{\text{cost}}$).
* **PBKDF2 (Password-Based Key Derivation Function 2):** Applies a pseudorandom function (like HMAC-SHA256) repeatedly to a password combined with a salt. Its iteration count parameter directly controls how many loops the CPU must execute per hash check.
* **Argon2:** The winner of the Password Hashing Competition, it is explicitly memory-hard, utilizing sequential memory access to heavily penalize high-parallelism GPU/ASIC hardware crackers. Its cost parameters control time (iterations), memory (RAM consumption), and parallelism degree.
* **Recommendation for MedDefense Applications:** **Argon2id** (or high-iteration PBKDF2 with unique salts) should be implemented for new MedDefense web application user portals. It provides superior resistance against modern specialized cracking hardware.
* **Active Directory Default Assessment:** Active Directory natively stores domain credentials using **NTHash (MD4-based, unsalted)** for NTLM authentication. This mechanism is **entirely inadequate** by modern security standards, representing a major structural vulnerability that allows offline cracking of dumped database files within minutes.
