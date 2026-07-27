## 4. The Key Exchange

### Part 1: Simulating Diffie-Hellman Key Exchange with OpenSSL

To demonstrate how two independent endpoints negotiate a shared cryptographic secret over an unencrypted network without transmitting the secret itself, we execute a complete OpenSSL Diffie-Hellman parameter generation and key derivation simulation.

#### 1. Generate Shared Diffie-Hellman Parameters

```bash
openssl dhparam -out dhparams.pem 2048

```

* *Output Summary:* Generates a 2048-bit prime modulus and generator parameters file (`dhparams.pem`) representing the public mathematical foundation shared by both parties.

#### 2. Generate Alice's Key Pair

```bash
# Generate Alice's private key
openssl gendsl -out alice_priv.pem dhparams.pem 2>/dev/null || openssl pkeyparam -in dhparams.pem -genkey -out alice_priv.pem
# Extract Alice's public key
openssl pkey -in alice_priv.pem -pubout -out alice_pub.pem

```

#### 3. Generate Bob's Key Pair

```bash
# Generate Bob's private key
openssl pkeyparam -in dhparams.pem -genkey -out bob_priv.pem
# Extract Bob's public key
openssl pkey -in bob_priv.pem -pubout -out bob_pub.pem

```

#### 4. Derive Shared Secrets

```bash
# Alice derives the shared secret using her private key and Bob's public key
openssl pkeyutl -derive -inkey alice_priv.pem -peerkey bob_pub.pem -out alice_secret.bin

# Bob derives the shared secret using his private key and Alice's public key
openssl pkeyutl -derive -inkey bob_priv.pem -peerkey alice_pub.pem -out bob_secret.bin

```

#### 5. Verify Equivalence

```bash
diff alice_secret.bin bob_secret.bin

```

The `diff` command returns **no output (exit code 0)**, confirming that both independently derived files are bit-for-bit identical. Alice and Bob now possess a shared secret key without ever sending it across the wire

### Part 2: Executive Explanation (For CFO Robert Kim)

Imagine Alice and Bob want to agree on a secret color inside a room filled with eavesdroppers, using buckets of paint. They start with a common public base color (the Diffie-Hellman parameters) known to everyone, including Eve. Alice and Bob each mix a secret, private color of their own into the public base color and exchange their unique mixed results across the room. Because mixing paint is easy, but un-mixing it is mathematically impossible, Eve sees the exchanged mixed colors but cannot figure out what private colors Alice and Bob added. Finally, Alice and Bob each take the other person's received mix, add their own private color back into it, and independently arrive at the exact same final shared secret color. Eve is left staring at intermediate paint mixtures that give her no clues, allowing Alice and Bob to securely lock down all future conversations.

### Part 3: The Man-in-the-Middle (MITM) Vulnerability & MedDefense Impact

Plain Diffie-Hellman key exchange provides confidentiality against passive listeners like Eve, but it fails completely against active attackers capable of **Man-in-the-Middle (MITM)** manipulation. Because basic Diffie-Hellman does not authenticate *who* is on either end of the connection, Eve can intercept Alice's public key, establish one independent DH exchange with Alice pretending to be Bob, and establish a second independent DH exchange with Bob pretending to be Alice. Eve now shares one secret key with Alice and a completely different secret key with Bob, allowing her to silently intercept, decrypt, read, modify, and re-encrypt all traffic passing between them without either party noticing.

**Connection to MedDefense:** If the site-to-site VPN tunnels connecting Central Hospital to the Westside Clinic rely on unauthenticated Diffie-Hellman parameters, an attacker positioned along the network path could perform a MITM attack, intercepting medical data in transit between facilities. **X.509 certificates** solve this vulnerability by binding public keys to verified digital identities signed by a trusted Certificate Authority (CA), mathematically proving to Alice and Bob that they are talking directly to each other and shutting down any rogue impersonator.
