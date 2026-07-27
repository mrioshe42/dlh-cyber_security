## 3. The Hash Laboratory

### Part 1: The Avalanche Effect

To analyze hash diffusion properties, the baseline string `"MedDefense"` and a slightly modified string `"MedDefense1"` were processed using SHA-256 and MD5.

#### Commands and Generated Hashes

# SHA-256 baseline and modified hashes
echo -n "MedDefense" | sha256sum
# Output: 39e026e107a44b2268e43e16e61033fdcc5d2bd62b23e03aca51db35c8671098
echo -n "MedDefense1" | sha256sum
# Output: 4d2e811ec3331b658d447d40e9d6bc9cb57423bf7a16e7807c4bc589a87d6092

# MD5 baseline and modified hashes
echo -n "MedDefense" | md5sum
# Output: 75d47fd4b4d183456d0f98fd9ba6ae4d
echo -n "MedDefense1" | md5sum
# Output: 0d2aed72043f78c2935e61ba8520306d


* **Avalanche Analysis:** Comparing the SHA-256 and MD5 hex outputs across these four hashes reveals that changing a single character ("1") alters roughly **50% to 60% of the resulting hexadecimal characters** due to complex non-linear bit mixing across rounds. Both SHA-256 and MD5 exhibit this strong avalanche effect, proving that output hashes do not leak structural similarities when inputs are perturbed.

### Part 2: Hash Collisions and the Birthday Problem

* **Unique Output Calculations & Powers of Two:**
  * MD5 (128-bit): 2^128 possible unique outputs (approx 3.4 x 10^38).
  * SHA-256 (256-bit): 2^256 possible unique outputs (approx 1.15 x 10^77).
* **Collision Vulnerability & Birthday Attacks:** Shorter hash functions (like MD5) have significantly smaller output spaces, making them vulnerable to **birthday attacks**—a mathematical probability model showing that collisions can be found in roughly the square root of the total possibilities ($2^{64}$ operations for MD5) rather than full brute-force space.
* **Connection to MedDefense Finding 018:** Active Directory’s support for legacy RC4/DES Kerberos tickets relies heavily on MD4/MD5 primitives internally. Because MD-family hashes are vulnerable to fast collision and pre-image attacks on modern hardware, an attacker who intercepts a Kerberoasting ticket encrypted with RC4 can crack user credentials offline in minutes, exposing enterprise accounts.

### Part 3: Rainbow Table Demonstration

#### 1. Unsalted Hash Lookup

* **Command:** `echo -n "password123" | md5sum` $\rightarrow$ `cbfdac6008f9cab4083784cbd1874f76`
* **CrackStation Reference:** Queried via **crackstation.net**.
* **Result:** Instantly matches plaintext `password123` because unsalted common hashes exist in precomputed rainbow tables globally.

#### 2. Salted Hash Lookup

* **Command:** `echo -n "s4lt9xQ2:password123" | md5sum` $\rightarrow$ `4a7a8d5173f27712f607c72957b0451a`
* **CrackStation Reference:** Queried via **crackstation.net**.
* **Result:** *"No hashes found."*
* **Operational Explanation:** Salting appends or prepends a random string before hashing, ensuring that identical passwords produce completely different hash outputs across different accounts. This completely neutralizes static rainbow tables because an attacker would need to precompute an entirely separate, massive rainbow table for every unique randomized salt used across the enterprise.

### Part 4: Key Stretching and Enterprise Recommendations

Unlike simple cryptographic hashes (like SHA-256 or MD5) which are intentionally engineered for extreme computing speed—allowing billions of checks per second on modest GPUs—key stretching functions are explicitly designed to be **deliberately slow and computationally expensive**. They prevent parallelized brute-force and dictionary attacks by intentionally burning CPU cycles, memory, or both per guess.

* **bcrypt:** A specialized password-hashing function built on the Blowfish cipher. It is a slow key-stretching hash that incorporates a built-in salt and a configurable cost factor (work factor) that increases the required computation exponentially on a logarithmic scale ($2^{\text{cost}}$). 
* **PBKDF2 (Password-Based Key Derivation Function 2):** A cryptographic key derivation function that applies a pseudorandom function (such as HMAC-SHA256) repeatedly to a password combined with a unique salt. Its iteration count parameter directly controls the number of CPU cycles required per guess, raising the computational work required to test password candidates.
* **Argon2:** The official winner of the Password Hashing Competition, built to be explicitly **memory-hard** to heavily penalize GPU and ASIC parallel cracking rigs. Its configurable cost parameters control time (iterations), memory (RAM consumption), and parallelism degree, forcing attackers to allocate massive amounts of physical memory per thread and rendering massive hardware-accelerated parallel cracking economically unviable.

* **Recommendation for MedDefense Applications:** **Argon2id** (or high-iteration PBKDF2 with unique salts) should be implemented for all new MedDefense web application user portals and databases. It provides superior, modern defense against specialized hardware-accelerated credential cracking.
* **Active Directory Default Assessment:** Active Directory natively stores domain credentials using **NTHash (MD4-based, unsalted)** for NTLM authentication. This mechanism is **entirely inadequate** by modern security standards, representing a major structural vulnerability that allows offline cracking of dumped database files within minutes.
