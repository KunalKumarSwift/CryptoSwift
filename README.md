# SACrypto

A Swift cryptography library for iOS built on Apple's CryptoKit, Security, and CommonCrypto frameworks. This library provides a clean, type-safe API covering symmetric encryption, asymmetric encryption, digital signatures, key agreement, key derivation, hashing, authentication, and secure storage.

---

## Table of Contents

- [Symmetric Encryption](#symmetric-encryption)
  - [AES-256-GCM](#aes-256-gcm)
  - [ChaCha20-Poly1305](#chacha20-poly1305)
  - [SASealedData](#sasealeddata)
- [Asymmetric Encryption](#asymmetric-encryption)
  - [RSA-OAEP](#rsa-oaep)
  - [Elliptic Curve Keys](#elliptic-curve-keys)
- [Digital Signatures](#digital-signatures)
  - [Ed25519](#ed25519)
  - [ECDSA](#ecdsa)
- [Key Agreement](#key-agreement)
  - [X25519 (Curve25519)](#x25519-curve25519)
  - [ECDH (NIST Curves)](#ecdh-nist-curves)
- [Key Derivation](#key-derivation)
  - [PBKDF2](#pbkdf2)
  - [Salt Generation](#salt-generation)
- [Hashing](#hashing)
  - [SHA-2 (SHA-256 / SHA-384 / SHA-512)](#sha-2)
  - [MD5 and SHA-1 (Legacy)](#md5-and-sha-1-legacy)
- [Authentication](#authentication)
  - [HMAC](#hmac)
- [Encoding Utilities](#encoding-utilities)
  - [Hex Encoding](#hex-encoding)
  - [Base64-URL Encoding](#base64-url-encoding)
- [Secure Random](#secure-random)
- [Keychain Storage](#keychain-storage)
- [Choosing the Right Algorithm](#choosing-the-right-algorithm)

---

## Symmetric Encryption

Symmetric encryption uses the **same key** to both encrypt and decrypt data. It is fast and suitable for encrypting large payloads. The key must be kept secret and shared securely between parties (typically via key agreement or key wrapping).

Both algorithms provided here are **Authenticated Encryption with Associated Data (AEAD)** schemes. This means they simultaneously provide:
- **Confidentiality** — only the key holder can read the plaintext.
- **Integrity** — any tampering with the ciphertext is detected before decryption.

---

### AES-256-GCM

**File:** `Sources/SACrypto/Symmetric/SAAESEncryptor.swift`

#### Theory

AES (Advanced Encryption Standard) is a block cipher standardised by NIST in 2001. It operates on 128-bit blocks and supports key sizes of 128, 192, or 256 bits. This library uses **AES-256**, the strongest variant.

GCM (Galois/Counter Mode) is a mode of operation that turns AES into a stream cipher and adds authentication. It requires a unique **nonce** (number used once) for every encryption. Reusing a nonce with the same key completely breaks the security of GCM — the library always generates a fresh cryptographic random nonce per call.

AES-GCM produces three outputs:
- **Nonce** (12 bytes) — the random IV used for this encryption.
- **Ciphertext** — the encrypted data, same length as the plaintext.
- **Tag** (16 bytes) — the authentication tag. Decryption verifies this before returning any plaintext, preventing attackers from feeding you tampered data.

#### When to use

Use AES-GCM when hardware AES acceleration is available (all modern iOS devices have AES-NI). It is the default choice for most applications.

#### Real-World Use Cases

- **Local file encryption** — encrypt documents, photos, or database files stored on device before writing to disk.
- **Secure local cache** — encrypt sensitive API responses (tokens, health data, financial records) cached on device.
- **End-to-end encrypted messaging** — after both parties establish a shared key via X25519, use AES-GCM to encrypt each message.
- **Encrypted backup** — encrypt user data before uploading to cloud storage so the server never sees plaintext.
- **Key wrapping** — use AES to encrypt another key (e.g. an RSA private key) for safe storage.

#### Usage

```swift
// Generate a key
let key = SAAESEncryptor.generateKey()  // 32-byte (256-bit) random key

// Encrypt
let plaintext = Data("hello world".utf8)
let sealed = try SAAESEncryptor.encrypt(plaintext, key: key)

// sealed.nonce      — 12 bytes
// sealed.ciphertext — same length as plaintext
// sealed.tag        — 16 bytes

// Decrypt
let recovered = try SAAESEncryptor.decrypt(sealed, key: key)

// Or use the combined (nonce + ciphertext + tag) blob
let blob = sealed.combined
let recovered2 = try SAAESEncryptor.decrypt(combined: blob, key: key)
```

---

### ChaCha20-Poly1305

**File:** `Sources/SACrypto/Symmetric/SAChaChaEncryptor.swift`

#### Theory

ChaCha20 is a stream cipher designed by Daniel Bernstein. Instead of operating on blocks like AES, it generates a keystream by running the ChaCha20 function with a key and nonce, then XORs it with the plaintext. Because XOR is its own inverse, the same operation decrypts.

Poly1305 is a one-time message authentication code. Combined with ChaCha20, it forms the **ChaCha20-Poly1305** AEAD construction, standardised in RFC 8439 and mandated in TLS 1.3.

Advantages over AES-GCM:
- Does not require hardware AES acceleration — software implementations are constant-time and immune to cache-timing attacks.
- Preferred on devices without AES hardware (e.g. older ARM cores).

Like AES-GCM, it produces a nonce (12 bytes), ciphertext, and a 16-byte authentication tag.

#### When to use

Use ChaCha20-Poly1305 on devices that lack hardware AES, or when you want a second independent cipher for defence-in-depth. Both ciphers are equally secure — the choice is performance-driven.

#### Real-World Use Cases

- **VPN / tunnel encryption** — WireGuard protocol uses ChaCha20-Poly1305 as its primary cipher.
- **TLS 1.3 traffic** — mandated as a cipher suite alongside AES-GCM.
- **Battery-sensitive apps** — on older or low-power devices without AES hardware, ChaCha20 is faster and uses less power.
- **Cross-platform libraries** — when building crypto that runs on non-Apple hardware without AES-NI, ChaCha20 guarantees consistent performance.

#### Usage

```swift
let key = SAChaChaEncryptor.generateKey()  // 32 bytes

let sealed = try SAChaChaEncryptor.encrypt(Data("secret".utf8), key: key)
let recovered = try SAChaChaEncryptor.decrypt(sealed, key: key)

// Combined blob works the same way
let recovered2 = try SAChaChaEncryptor.decrypt(combined: sealed.combined, key: key)
```

---

### SASealedData

**File:** `Sources/SACrypto/Symmetric/SASealedData.swift`

A value type that holds the three components of an authenticated encryption result: `nonce`, `ciphertext`, and `tag`. The `combined` property serialises them as `nonce || ciphertext || tag`, compatible with CryptoKit's own SealedBox representation.

```swift
let sealed = SASealedData(nonce: nonce, ciphertext: ct, tag: tag)
let blob   = sealed.combined  // transmit or store this
```

---

## Asymmetric Encryption

Asymmetric (public-key) encryption uses a **key pair**: a public key (shareable) and a private key (secret). Anyone with the public key can encrypt; only the private key holder can decrypt.

---

### RSA-OAEP

**File:** `Sources/SACrypto/Asymmetric/SARSACipher.swift`

#### Theory

RSA (Rivest–Shamir–Adleman, 1977) is based on the mathematical difficulty of factoring the product of two large prime numbers. The security of RSA scales with key size:
- **2048-bit** — minimum acceptable for new applications (~112 bits of security).
- **3072-bit** — ~128-bit security (equivalent to AES-128).
- **4096-bit** — ~140-bit security, highest commonly used.

OAEP (Optimal Asymmetric Encryption Padding) adds randomised padding before encryption, ensuring that encrypting the same plaintext twice gives different ciphertexts (preventing chosen-plaintext attacks). This library uses **RSA-OAEP-SHA256**.

**Important limitation:** RSA can only encrypt small payloads. For a 2048-bit key, the maximum plaintext is 190 bytes. For bulk data, use the **hybrid encryption** pattern: encrypt an AES key with RSA, then encrypt the data with AES.

#### Real-World Use Cases

- **Hybrid encryption** — encrypt a randomly generated AES key with the recipient's RSA public key, then encrypt the actual data with AES. The recipient decrypts the AES key with their RSA private key, then decrypts the data.
- **Secure onboarding** — a server shares its RSA public key; a mobile client encrypts a session key or device identity token on first launch.
- **License / entitlement delivery** — a server encrypts a license blob with the device's public key; only that device can decrypt it.
- **Encrypted email (S/MIME)** — S/MIME uses RSA to wrap the symmetric content-encryption key.
- **Key exchange in legacy systems** — interoperating with existing infrastructure (HSMs, PKI) that requires RSA.

#### Usage

```swift
// Generate a key pair
let pair = try SARSACipher.generateKeyPair(keySize: .bits2048)

// Encrypt (with recipient's public key)
let ciphertext = try SARSACipher.encrypt(
    Data("wrap an AES key here".utf8),
    publicKeyData: pair.publicKeyData
)

// Decrypt (with your private key)
let plaintext = try SARSACipher.decrypt(ciphertext, privateKeyData: pair.privateKeyData)

// Hybrid encryption pattern (recommended for large data)
let aesKey  = SAAESEncryptor.generateKey()
let wrapped = try SARSACipher.encrypt(aesKey, publicKeyData: recipientPublicKey)
let sealed  = try SAAESEncryptor.encrypt(largeData, key: aesKey)
// Transmit: wrapped + sealed.combined
```

---

### Elliptic Curve Keys

**File:** `Sources/SACrypto/Asymmetric/SAECKeyPair.swift`

Generates DER-encoded EC key pairs for use with ECDSA signatures and ECDH key agreement over NIST curves P-256, P-384, and P-521.

```swift
// For signing (ECDSA)
let signingPair = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)
// signingPair.privateKeyDER — PKCS#8 format
// signingPair.publicKeyDER  — SubjectPublicKeyInfo format

// For key agreement (ECDH)
let agreementPair = SAECKeyGenerator.generateKeyAgreementPair(curve: .p384)
```

---

## Digital Signatures

A digital signature proves that a message was created by a specific private key holder and has not been altered. The signer uses their **private key** to sign; anyone with the corresponding **public key** can verify.

---

### Ed25519

**File:** `Sources/SACrypto/Signatures/SAEd25519Signer.swift`

#### Theory

Ed25519 is an Edwards-curve Digital Signature Algorithm (EdDSA) using Curve25519 (specifically the twisted Edwards form). It was designed by Bernstein et al. and is widely considered the best general-purpose signature algorithm available today.

Key properties:
- **32-byte keys** — compact and fast to generate.
- **64-byte signatures** — small and constant-size.
- **Deterministic** — the same key and message always produce the same signature (no randomness required at signing time, unlike ECDSA). This eliminates the catastrophic failure mode where a broken random number generator leaks the private key.
- **Fast** — extremely fast verification and signing in software.
- **Secure** — immune to several side-channel attacks that affect ECDSA.

Ed25519 is mandatory in SSH, used in TLS 1.3, Signal Protocol, and many modern systems.

#### Real-World Use Cases

- **API request signing** — sign each request with a device private key so the server can verify the request came from a genuine registered device (prevents request forgery).
- **Software update verification** — the app verifies a signature on the update manifest before downloading, ensuring updates come from the legitimate developer.
- **Passwordless authentication** — the server stores only the user's public key. The user proves identity by signing a server challenge with their private key (FIDO2 / passkeys pattern).
- **Document signing** — sign contracts, consent forms, or audit logs to prove they have not been altered after creation.
- **JWT signing (EdDSA)** — sign JSON Web Tokens for stateless authentication without a database lookup.
- **Blockchain / wallet transactions** — most modern blockchains (Solana, Cardano, Monero) use Ed25519 for transaction signing.

#### Usage

```swift
// Generate
let pair = SAEd25519Signer.generateKeyPair()
// pair.privateKeyData — 32 bytes
// pair.publicKeyData  — 32 bytes

// Sign
let message   = Data("important document".utf8)
let signature = try SAEd25519Signer.sign(message, privateKeyData: pair.privateKeyData)
// signature is always 64 bytes

// Verify
let isValid = try SAEd25519Signer.verify(
    signature,
    for: message,
    publicKeyData: pair.publicKeyData
)
```

---

### ECDSA

**File:** `Sources/SACrypto/Signatures/SAECDSASigner.swift`

#### Theory

ECDSA (Elliptic Curve Digital Signature Algorithm) is a variant of DSA using elliptic curve cryptography over NIST curves P-256, P-384, or P-521. Each curve provides a different security level:
- **P-256** — 128-bit security. Most widely deployed (used in TLS, FIDO2, Apple Secure Enclave).
- **P-384** — 192-bit security. Used in FIPS 140 and government/classified contexts.
- **P-521** — 260-bit security. Highest level, rare in practice.

Unlike Ed25519, ECDSA signatures are **non-deterministic** by default (they require a random nonce per signature). A weak or reused nonce can leak the private key — a real-world vulnerability that has compromised Bitcoin wallets and Sony's PlayStation 3. Apple's CryptoKit uses RFC 6979 deterministic nonce generation to avoid this, making it safe in practice.

Use ECDSA when you need **NIST P-curve compatibility** (e.g. FIPS 140, TLS client certificates, HSMs, government requirements). Otherwise prefer Ed25519.

#### Real-World Use Cases

- **TLS client certificates** — ECDSA P-256 is the standard for mutual TLS (mTLS) client authentication in enterprise and government environments.
- **Apple Secure Enclave** — the Secure Enclave generates and uses P-256 ECDSA keys that never leave the hardware.
- **FIDO2 / WebAuthn** — the platform authenticator (Face ID, Touch ID) signs challenges with P-256 ECDSA.
- **Code signing** — Apple's code signing infrastructure uses ECDSA certificates.
- **FIPS 140 compliance** — any application requiring FIPS 140-2/3 validated cryptography must use NIST-approved curves (P-256, P-384, P-521).
- **JWT signing (ES256/ES384/ES512)** — ECDSA variants for signing JSON Web Tokens in standards-compliant systems.

#### Usage

```swift
let pair = SAECKeyGenerator.generateSigningKeyPair(curve: .p256)

let signature = try SAECDSASigner.sign(
    message,
    privateKeyDER: pair.privateKeyDER,
    curve: .p256
)

let isValid = try SAECDSASigner.verify(
    signature,
    for: message,
    publicKeyDER: pair.publicKeyDER,
    curve: .p256
)
```

---

## Key Agreement

Key agreement protocols allow two parties to derive a **shared secret** over an insecure channel, without ever transmitting the secret itself. Both sides end up with the same key.

---

### X25519 (Curve25519)

**File:** `Sources/SACrypto/KeyAgreement/SAX25519Agreement.swift`

#### Theory

X25519 is a Diffie-Hellman key agreement function using Curve25519. It is the recommended algorithm for new code.

**How Diffie-Hellman works (conceptually):**
1. Alice generates a key pair (private scalar, public point).
2. Bob generates a key pair.
3. Alice computes `shared = Alice_private * Bob_public`.
4. Bob computes `shared = Bob_private * Alice_public`.
5. Due to the math of elliptic curves, both sides arrive at the same point.
6. An eavesdropper who sees both public keys cannot compute the shared secret without solving the Elliptic Curve Discrete Logarithm Problem (ECDLP), which is computationally infeasible.

The raw shared secret is then passed through **HKDF-SHA256** (a key derivation function) to produce a uniformly distributed symmetric key. HKDF also allows domain separation via salt and context info parameters.

X25519 advantages over NIST curves:
- No special-case points to worry about.
- Constant-time implementation is straightforward.
- Faster than P-256 in software.
- Mandatory in TLS 1.3.

#### Real-World Use Cases

- **End-to-end encrypted messaging** — Signal Protocol uses X25519 for its Double Ratchet key exchange, providing forward secrecy (compromising today's key does not expose past messages).
- **TLS 1.3 handshake** — X25519 is the most commonly negotiated key exchange in modern HTTPS connections.
- **Secure peer-to-peer communication** — two devices exchange public keys out-of-band (e.g. via QR code), then use X25519 to derive a shared encryption key without a server in the middle.
- **Forward-secret session keys** — generate a new ephemeral key pair for each session so that recording encrypted traffic today cannot be decrypted later even if a long-term key is compromised.
- **Sealed sender** — derive a shared key with a recipient's long-term public key to send an encrypted message without revealing your identity as the sender.

#### Usage

```swift
// Both parties generate key pairs and share public keys
let alice = SAX25519Agreement.generateKeyPair()
let bob   = SAX25519Agreement.generateKeyPair()

// Alice derives shared key using her private + Bob's public
let aliceKey = try SAX25519Agreement.sharedSymmetricKey(
    myPrivateKeyData: alice.privateKeyData,
    peerPublicKeyData: bob.publicKeyData,
    salt: Data("session-id".utf8),  // optional context
    outputByteCount: 32
)

// Bob derives shared key using his private + Alice's public
let bobKey = try SAX25519Agreement.sharedSymmetricKey(
    myPrivateKeyData: bob.privateKeyData,
    peerPublicKeyData: alice.publicKeyData,
    salt: Data("session-id".utf8),
    outputByteCount: 32
)

// aliceKey == bobKey — now use for AES or ChaCha20
let sealed = try SAAESEncryptor.encrypt(message, key: aliceKey)
```

---

### ECDH (NIST Curves)

**File:** `Sources/SACrypto/KeyAgreement/SAECDHAgreement.swift`

Same Diffie-Hellman principle as X25519 but using NIST P-256, P-384, or P-521 curves. The raw secret is passed through HKDF (using SHA-256, SHA-384, or SHA-512 respectively).

Use this when interoperating with systems that require NIST curves (e.g. FIPS environments).

#### Real-World Use Cases

- **FIPS-compliant key exchange** — government and financial systems often mandate NIST P-256 or P-384 for key agreement.
- **ECIES (Elliptic Curve Integrated Encryption Scheme)** — combine ECDH with AES-GCM to encrypt messages for a recipient using only their public key, without a prior shared secret.
- **HSM interoperability** — hardware security modules typically expose NIST curve ECDH rather than X25519.
- **TLS in enterprise** — corporate environments using FIPS-validated TLS stacks require P-256/P-384 key exchange.

```swift
let alice = SAECKeyGenerator.generateKeyAgreementPair(curve: .p256)
let bob   = SAECKeyGenerator.generateKeyAgreementPair(curve: .p256)

let shared = try SAECDHAgreement.sharedSymmetricKey(
    myPrivateKeyDER: alice.privateKeyDER,
    peerPublicKeyDER: bob.publicKeyDER,
    curve: .p256,
    outputByteCount: 32
)
```

---

## Key Derivation

Key derivation functions (KDFs) convert a low-entropy secret (like a password) into a high-entropy cryptographic key. They are intentionally slow to resist brute-force and dictionary attacks.

---

### PBKDF2

**File:** `Sources/SACrypto/KeyDerivation/SAKeyDerivation.swift`

#### Theory

PBKDF2 (Password-Based Key Derivation Function 2, RFC 2898) derives a key from a password by:
1. Combining the password with a random **salt** to prevent rainbow table attacks.
2. Applying a pseudo-random function (HMAC-SHA256 or HMAC-SHA512) repeatedly for a configurable number of **iterations**.
3. The iteration count is a work factor — higher iterations mean slower derivation, making brute-force proportionally slower.

The salt ensures that two users with the same password get different derived keys. The salt is not secret — it is stored alongside the derived key (or its hash).

**Iteration recommendations (as of 2023):**
- NIST recommends ≥ 600,000 iterations for PBKDF2-HMAC-SHA256.
- The library defaults to 100,000 (a safe minimum for many use cases).

For newer applications, consider scrypt or Argon2 (not in this library) which are memory-hard and more resistant to GPU/ASIC attacks.

#### Real-World Use Cases

- **Login / authentication** — derive a verification key from the user's password and a stored salt. Store the derived key, not the password. On login, re-derive and compare.
- **Encrypted local vault** — derive an AES key from the user's PIN/passphrase to encrypt sensitive data stored on device (notes, passwords, private keys).
- **Password-protected exports** — derive a key from a user-chosen password to encrypt an exported file (e.g. wallet backup, health records export).
- **Master key from passphrase** — derive a master key that is then used to wrap/unwrap per-item encryption keys, so changing the password only requires re-wrapping the master key, not re-encrypting all data.
- **Zero-knowledge authentication** — derive a key on the client side and use it to authenticate without sending the raw password to the server.

#### Usage

```swift
let salt = SASaltGenerator.generate()  // 32 random bytes

let key = try SAKeyDerivation.deriveKey(
    fromPassword: "user-password",
    salt: salt,
    iterations: 600_000,       // NIST 2023 recommendation
    keyByteCount: 32,          // 256-bit AES key
    algorithm: .pbkdf2SHA256
)

// Store salt alongside the derived key (or its hash)
// Never store the password itself
```

---

### Salt Generation

**File:** `Sources/SACrypto/KeyDerivation/SASaltGenerator.swift`

Generates cryptographically secure random salts. Always generate a new salt for each password — never reuse salts.

#### Real-World Use Cases

- **Per-user salts** — generate and store a unique salt for each user account so two users with the same password produce different derived keys.
- **Per-record encryption** — generate a fresh salt for each piece of data to ensure keys are never reused across records.
- **Nonce generation** — when a specific-length nonce is needed for protocols that manage their own nonce format.

```swift
let salt16 = SASaltGenerator.generate(byteCount: 16)  // 128-bit salt
let salt32 = SASaltGenerator.generate()               // 256-bit salt (default)
```

---

## Hashing

A cryptographic hash function maps arbitrary data to a fixed-length digest. It is a one-way function — computing the digest is easy; recovering the input from the digest is computationally infeasible.

Properties of a secure hash:
- **Pre-image resistance** — given a hash, you cannot find the input.
- **Collision resistance** — it is infeasible to find two different inputs with the same hash.
- **Avalanche effect** — a single bit change in the input completely changes the output.

---

### SHA-2

**File:** `Sources/SACrypto/Hashing/SAHasher.swift`

The SHA-2 family (Secure Hash Algorithm 2) was designed by the NSA and standardised by NIST. It is the current standard for most applications.

| Variant  | Output size | Security level | Common use |
|----------|-------------|----------------|------------|
| SHA-256  | 32 bytes    | 128-bit        | General purpose, TLS, Bitcoin |
| SHA-384  | 48 bytes    | 192-bit        | TLS certificates, government |
| SHA-512  | 64 bytes    | 256-bit        | Maximum strength |

#### Real-World Use Cases

- **Password storage (not alone)** — never hash passwords with SHA-256 directly (use PBKDF2). But SHA-256 is appropriate for hashing a derived key's verification tag.
- **File integrity verification** — hash a downloaded file and compare against a published digest to detect corruption or tampering.
- **Content addressing** — use the hash as a unique identifier for a piece of data (Git object IDs, IPFS CIDs, deduplication keys).
- **Commitment schemes** — publish a hash of a value before revealing it, proving you knew it without disclosing it early.
- **Certificate fingerprinting** — identify a TLS certificate by its SHA-256 digest (certificate pinning).
- **Blockchain / Merkle trees** — SHA-256 is the hash function in Bitcoin's proof-of-work and Merkle tree construction.
- **Data deduplication** — hash file chunks to detect duplicates without comparing raw bytes.

#### Usage

```swift
// Hash data
let digest = SAHasher.hash(Data("hello".utf8), using: .sha256)

// Hash a string directly
let hex = SAHasher.hexString("hello world", using: .sha256)

// Different variants
let d384 = SAHasher.hash(data, using: .sha384)
let d512 = SAHasher.hash(data, using: .sha512)
```

---

### MD5 and SHA-1 (Legacy)

**File:** `Sources/SACrypto/Hashing/SAInsecureHasher.swift`

**These algorithms are cryptographically broken and must not be used for security purposes.**

- **MD5** — Practical collision attacks have existed since 2004. Do not use for integrity checking or digital signatures.
- **SHA-1** — SHAttered collision attack demonstrated in 2017 by Google. Deprecated by NIST and most CAs.

They are provided solely for interoperability with legacy systems (e.g. checksums in older file formats, non-security identifiers).

#### Real-World Use Cases (Legacy Interoperability Only)

- **Gravatar avatars** — Gravatar uses MD5 of an email address as the avatar URL key.
- **Legacy API compatibility** — some older REST APIs require MD5 checksums for request validation.
- **Git object format** — Git historically used SHA-1 for object IDs (migrating to SHA-256).
- **Checksums in older file formats** — some archive formats (ZIP, older firmware images) embed MD5 or SHA-1 checksums for corruption detection (not tamper detection).

```swift
// Legacy use only
let md5hex  = SAInsecureHasher.md5HexString("hello world")
let sha1hex = SAInsecureHasher.sha1HexString(Data([0x01, 0x02]))
```

---

## Authentication

### HMAC

**File:** `Sources/SACrypto/Authentication/SAHMAC.swift`

#### Theory

HMAC (Hash-based Message Authentication Code) combines a cryptographic hash function with a secret key to produce a **MAC** — a short tag proving both the **integrity** and **authenticity** of a message.

Unlike a plain hash, HMAC requires the secret key to produce or verify the tag. An attacker who can modify the message cannot produce a valid MAC without the key.

Construction: `HMAC(key, message) = H((key XOR opad) || H((key XOR ipad) || message))`

The inner and outer hash applications with ipad/opad provide a domain separation that prevents length-extension attacks.

HMAC is used in:
- API request signing (AWS SigV4, JWT HS256)
- TLS record authentication (before AEAD was standard)
- PBKDF2 (as its internal PRF)

**Verification uses constant-time comparison** to prevent timing attacks — an attacker cannot determine how many bytes of a guessed MAC are correct by measuring response time.

#### Real-World Use Cases

- **Webhook verification** — GitHub, Stripe, and most webhook providers sign payloads with HMAC-SHA256. The receiver recomputes the MAC and compares it to detect forged or replayed webhooks.
- **API request signing (AWS SigV4)** — AWS uses HMAC-SHA256 to sign every API request, preventing request tampering and replay attacks.
- **JWT HS256 tokens** — JSON Web Tokens using the HS256 algorithm are signed with HMAC-SHA256. The server verifies the token on every request without a database lookup.
- **Cookie integrity** — sign session cookies so the server can detect tampering without encrypting the cookie contents.
- **Data pipeline integrity** — attach an HMAC to records flowing through a pipeline so each stage can verify the record has not been altered in transit.
- **Challenge-response authentication** — server sends a random challenge; client responds with HMAC(challenge, sharedSecret), proving it knows the secret without revealing it.

#### Usage

```swift
let key  = Data("secret-key".utf8)
let data = Data("message to authenticate".utf8)

// Authenticate
let mac = SAHMAC.authenticate(data, key: key, using: .sha256)

// Verify (constant-time)
let valid = SAHMAC.verify(data, mac: mac, key: key, using: .sha256)

// Other algorithms
let mac512 = SAHMAC.authenticate(data, key: key, using: .sha512)
```

---

## Encoding Utilities

**File:** `Sources/SACrypto/Encoding/SACryptoEncoding.swift`

Extensions on `Data` for common encoding formats.

### Hex Encoding

Encodes binary data as a lowercase hexadecimal string. Useful for logging, debugging, and comparing digests.

```swift
let data = Data([0xDE, 0xAD, 0xBE, 0xEF])
let hex  = data.hexString           // "deadbeef"
let back = Data(hexString: "deadbeef")  // original bytes
```

### Base64-URL Encoding

Base64-URL (RFC 4648 §5) is a variant of Base64 that replaces `+` with `-` and `/` with `_`, and omits `=` padding. It is safe to embed in URLs and JSON without percent-encoding, making it ideal for JWTs and web APIs.

```swift
let encoded = data.base64URLEncoded          // URL-safe, no padding
let decoded = Data(base64URLEncoded: encoded)
```

---

## Secure Random

**File:** `Sources/SACrypto/Random/SASecureRandom.swift`

#### Theory

Cryptographic operations require random numbers that are **unpredictable** to an attacker. Standard pseudo-random number generators (like `arc4random` or `drand48`) are not suitable — they are seeded with low-entropy values and are predictable.

`SecRandomCopyBytes` reads from the operating system's entropy pool (`/dev/random` equivalent), which is seeded from hardware entropy sources (thermal noise, interrupt timing, etc.). This provides true cryptographic randomness.

#### Real-World Use Cases

- **Key generation** — all symmetric and asymmetric key generation internally relies on the OS entropy pool.
- **Nonce / IV generation** — AES-GCM and ChaCha20 require a unique nonce per encryption; this generates them.
- **Salt generation** — PBKDF2 salts must be random; SASaltGenerator delegates to SASecureRandom.
- **Token generation** — generate unpredictable session tokens, CSRF tokens, or password reset codes.
- **OTP codes** — generate one-time codes for two-factor authentication flows.
- **Random sampling / shuffle** — `uniformRandom(upperBound:)` provides unbiased random integers for secure card shuffle, lottery draws, or random sampling in sensitive contexts.

```swift
// Random bytes (for keys, nonces, salts)
let bytes = SASecureRandom.bytes(count: 32)

// Random integers
let n32 = SASecureRandom.uint32()
let n64 = SASecureRandom.uint64()

// Uniformly random in [0, upperBound) — rejection sampling to avoid modulo bias
let die  = SASecureRandom.uniformRandom(upperBound: 6)
```

---

## Keychain Storage

**File:** `Sources/SACrypto/Keychain/SAKeychain.swift`

The iOS Keychain provides hardware-backed secure storage for sensitive data. Items are encrypted using the device's Secure Enclave and are protected by the device passcode.

This library stores items with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`:
- Data is only readable when the device is **unlocked**.
- Data is **never synced** to iCloud or backed up.
- Data is tied to this specific device.

#### Real-World Use Cases

- **Storing AES encryption keys** — encrypt a document with AES and store the key in the Keychain so it survives app restarts but cannot be extracted from a device backup.
- **OAuth / API tokens** — store access tokens and refresh tokens so they are not accessible in the app sandbox or backups.
- **Private key storage** — store Ed25519 or ECDSA private keys for signing operations; the key never appears in memory longer than necessary.
- **Biometric-protected secrets** — combine with `kSecAttrAccessControl` and Face ID / Touch ID to require biometric confirmation before a key is returned.
- **Derived key caching** — derive a PBKDF2 key once on login, store it temporarily in the Keychain, and delete it on logout, avoiding repeated slow derivation.
- **Certificate pinning hashes** — store the expected server certificate fingerprint so it cannot be modified by a compromised app update delivery.

```swift
let aesKey = SAAESEncryptor.generateKey()

// Store
try SAKeychain.store(aesKey, forKey: "com.myapp.aes-key")

// Retrieve
let recovered = try SAKeychain.retrieve(forKey: "com.myapp.aes-key")

// Check existence
let exists = SAKeychain.exists(forKey: "com.myapp.aes-key")

// Delete
try SAKeychain.delete(forKey: "com.myapp.aes-key")
```

---

## Choosing the Right Algorithm

| Goal | Recommended | Alternative |
|------|-------------|-------------|
| Encrypt data with a shared key | AES-256-GCM | ChaCha20-Poly1305 |
| Encrypt data without hardware AES | ChaCha20-Poly1305 | — |
| Encrypt for a recipient (public key) | RSA-OAEP + AES (hybrid) | — |
| Sign a message | Ed25519 | ECDSA P-256 (FIPS) |
| Establish a shared key over network | X25519 | ECDH P-256 (FIPS) |
| Derive a key from a password | PBKDF2-SHA256 | PBKDF2-SHA512 |
| Hash data (integrity check) | SHA-256 | SHA-512 |
| Authenticate a message with a key | HMAC-SHA256 | HMAC-SHA512 |
| Store sensitive data on device | SAKeychain | — |
| Generate random bytes / keys / nonces | SASecureRandom | — |

### Common Patterns

**Secure message to a known recipient:**
```
1. Recipient shares their X25519 public key.
2. Sender calls SAX25519Agreement.sharedSymmetricKey().
3. Sender encrypts message with SAAESEncryptor using the shared key.
4. Recipient performs the same key agreement and decrypts.
```

**Password-protected local data:**
```
1. Generate a random salt with SASaltGenerator.
2. Derive a key from the user's password with SAKeyDerivation.
3. Encrypt data with SAAESEncryptor.
4. Store salt (non-secret) and ciphertext. Never store the password.
```

**Signed API request:**
```
1. Generate an Ed25519 key pair. Store private key in SAKeychain.
2. Sign the request body with SAEd25519Signer.
3. Send the request with the signature and your public key.
4. Server verifies the signature.
```

---

## Requirements

- iOS 15+
- Swift 6.0+
- Xcode 15+

## Dependencies

None. Built entirely on Apple system frameworks: CryptoKit, Security, and CommonCrypto.
