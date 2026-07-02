# Cryptography & Side-Channel Playbook

Whitehat crypto-implementation audit: algorithm/mode/parameter review, timing
side-channels, secret zeroization, Wycheproof differential testing, and protocol
modeling. Remediation-oriented. AUTHORIZED testing only — audit code/configs the
operator provides; refuse to weaken, break, or backdoor cryptography.

Core thesis (crypto-audit): *most* crypto failures are not "they used MD5." They
are right-primitive-wrong-mode (ECB not GCM), right-algorithm-wrong-parameter
(PBKDF2 @ 1,000 iters in 2026), right-library-wrong-call-order (cipher init after
data loaded), or the bug is invisible at source level and only appears in the
emitted assembly (DSE-eliminated wipe, secret-dependent `DIV`). Audit for the
subtle class.

---

## When this applies

Route an engagement here when the target shows any of:

- **Custom or homegrown crypto** — any "we built our own encryption/signing." The
  default verdict (crypto-audit) is "use libsodium / Tink / WebCrypto instead";
  <50 people on Earth design new crypto safely and they don't work here. Custom
  crypto is a finding unless an explicit threat model says otherwise.
- **Primitive/library calls**: `AES`, `Cipher.getInstance`, `AESGCM`, `createCipher`,
  `pkcs1_v1_5`, `PBKDF2`, `HKDF`, `Argon2`, `scrypt`, `bcrypt`, `jwt.decode`,
  `libsodium`, `BoringSSL`, `cryptography.hazmat`, OpenSSL.
- **Secret-handling native code** (C/C++/Rust/Go/Swift) — keys, seeds, nonces,
  private exponents, passwords, tokens. Triggers constant-time + zeroize passes.
- **Functions named** `sign`, `verify`, `encrypt`, `decrypt`, `derive_key`,
  `kdf`, or code with `/`/`%`/`<<` on secret-derived values, or `if (secret_bit)`.
- **TLS endpoints** you're authorized to test; cipher-suite / cert config.
- **A protocol** to reason about — handshake, key exchange, MPC, threshold sig,
  RFC, academic paper, or ProVerif/Tamarin model (diagram before you attack).
- Keywords: nonce reuse, IV reuse, AES-GCM, padding oracle, signature verification,
  constant-time, timing attack, KyberSlash, side-channel, Wycheproof, zeroize.

---

## Methodology

1. **Inventory primitives (recon).** Grep the codebase for every primitive,
   mode, KDF, RNG, and TLS config in use. Build a key inventory table
   (key → purpose → location → algorithm → rotation). Flag every hardcoded
   algorithm/key-size for crypto-agility (a CBOM is the first PQC-migration step).
2. **Classify each finding by failure mode**, not by primitive: (a) algorithm/mode
   wrong, (b) parameter wrong, (c) call-order/usage wrong, (d) side-channel,
   (e) randomness, (f) protocol logic. The subtle classes (c, d, f) are where
   experts earn their fee.
3. **Algorithm + mode pass.** Reject ECB, unauthenticated CBC/CTR, DES/3DES, RC4,
   raw RSA, PKCS#1 v1.5 *encryption* padding. Require AEAD (AES-GCM /
   ChaCha20-Poly1305) or Encrypt-then-MAC with separate keys.
4. **Parameter pass.** Check KDF iteration counts / memory cost, key sizes, curve
   choices, bcrypt cost, nonce/IV length. State the concrete number, not "weak."
5. **IV/nonce + usage pass.** Hunt nonce reuse, hardcoded/zero IVs, library
   defaults that silently pick ECB or derive IV from key. This is a top-3 source
   of "looks right, leaks plaintext."
6. **Signature/verification pass.** The bug is usually *not checking* the sig, or
   trusting `alg` from the message (JWT `alg:none`), or non-constant-time compare,
   or no replay window. Verify-before-parse for webhooks.
7. **Side-channel pass.** For secret-handling native code, run the constant-time
   analyzer at multiple `--arch` and `--opt-level`; triage each flagged op by data
   flow (does the operand depend on a secret?); confirm statistically with dudect
   and locate with Timecop.
8. **Zeroization pass.** For C/C++/Rust handling secrets, check wipes exist, cover
   all paths, use the right size, and *survive the optimizer* — prove DSE with an
   O0-vs-O2 IR diff. Never accept "optimized away" without compiler evidence.
9. **Differential / known-attack pass.** Run Wycheproof vectors against the
   implementation (valid/invalid/acceptable) to catch malleability, bad DER,
   invalid-curve, tag-forgery, padding-oracle classes.
10. **Protocol pass.** Extract the message flow into a sequence diagram with crypto
    annotations; compare implementation against the canonical spec; flag every
    divergence (missing MAC, omitted abort path) with `⚠️`.
11. **TLS posture.** Scan with `testssl.sh` / `sslyze`; map versions, ciphers,
    cert chain, known-CVE exposure.
12. **Verify fixes at runtime.** Crypto changes fail *silently* — round-trip
    encrypt/decrypt after every change; verify KMS IAM covers both encrypt AND
    decrypt; plan hash-algo migration via rehash-on-login.

---

## High-signal checklist (CROWN JEWELS — preserve verbatim)

### Algorithm / mode (crypto-audit)
- **Symmetric:** require AES-256-GCM or ChaCha20-Poly1305 (AEAD). **Reject** AES-ECB
  (identical plaintext → identical ciphertext), AES-CBC w/o HMAC (padding oracle),
  AES-CTR w/o HMAC (bit-flip = plaintext-flip), DES/3DES (Sweet32, 64-bit block),
  RC4, Blowfish.
- **Asymmetric:** Ed25519 / X25519; RSA-OAEP / RSA-PSS at 3072+ bits if forced;
  **never** RSA PKCS#1 v1.5 padding for encryption (Bleichenbacher); never raw RSA.
- **MAC:** HMAC-SHA256 minimum; never CBC-MAC; never homemade `hash(key + message)`.
- **Passwords (categorically different):** Argon2id, scrypt (N=2^17,r=8,p=1), or
  bcrypt cost ≥ 12 (OWASP 2024 floor).
- **Grep:** `MD5`, `SHA1` (outside legacy HMAC-SHA1), `DES`, `RC4`, `Blowfish`,
  `AES.*ECB`, `pkcs1_v1_5`, `RSA.encrypt` without OAEP.

### IV / nonce (crypto-audit) — top-3 leak source
- **AES-GCM:** unique 96-bit random nonce per encryption under a key. **NEVER reuse**
  — reuse gives the attacker XOR of two plaintexts AND forgery capability. High
  volume → AES-GCM-SIV (nonce-misuse-resistant).
- **AES-CBC:** IV unpredictable AND unique, random 16 bytes per encryption.
- **ChaCha20-Poly1305:** unique nonce/message; XChaCha20 (192-bit) safe with random.
- **Grep for default-ECB / weak-IV footguns:** `Cipher.getInstance("AES")` (Java
  default = ECB), `AES.new(key)` (PyCryptodome default = ECB),
  `crypto.createCipher` (Node — deprecated, derives IV from key), `iv = bytes(16)`,
  `iv = "0000000000000000"`, zero-IV constructors, counter resets.

### Key derivation (crypto-audit / 13-crypto-analysis)
- **From password:** Argon2id, or PBKDF2-HMAC-SHA256 ≥ 600,000 iterations
  (NIST/OWASP 2023+), or scrypt N=2^17. PBKDF2-SHA1 ≥ 1,300,000; PBKDF2-SHA512
  ≥ 210,000 iterations.
- **From high-entropy secret:** HKDF-SHA256 (correct primitive for sub-key derivation).
- **Grep:** `PBKDF2` (check `iterations` arg), `pbkdf2_hmac`, `HKDF`, `Argon2`, `scrypt`.
- Argon2id OWASP floor: `m=19456` (19 MB), `t=2`, `p=1`; strong: `m=65536`, `t=3`, `p=4`.

### Authenticated encryption (crypto-audit)
- Always check MAC → then decrypt (never decrypt → check MAC; that's a padding oracle).
- Encrypt-then-MAC must use **separate** enc/auth keys (or HKDF-derive both from master).
- Constant-time MAC compare: `crypto.timingSafeEqual` (Node),
  `hmac.compare_digest` (Python), `subtle.ConstantTimeCompare` (Go),
  `CRYPTO_memcmp` (OpenSSL).

### Signature verification (crypto-audit)
- **JWT:** verify `alg` is *exactly* what you expect; never use `jwt.decode` claims
  without `jwt.verify`; many libs accept `alg: 'none'` (unsigned) by default — pin it.
- **Webhooks:** verify signature BEFORE parsing the body (parse-then-verify = attack
  surface).
- Constant-time compare on the signature bytes; enforce a ±5-min timestamp replay
  window (Stripe/GitHub/Slack), not "forever."
- **Grep:** `jwt.decode` without subsequent `verify`, `alg: 'none'`, `verify.*sig`
  with no `timingSafeEqual` nearby.

### Randomness (crypto-audit / 13-crypto-analysis)
- **Use:** `crypto.randomBytes`, `secrets.token_bytes`, `os.urandom`, `crypto/rand`,
  `SecRandomCopyBytes`, `SecureRandom`.
- **Never:** `Math.random()`, `random.random()`/`random.randint()`, C `rand()`,
  `mt_rand` (PHP), `Random.new` (Ruby) for any security purpose.
- Token/session-ID entropy floor 128 bits (16 random bytes); 256 bits the sane default.

### Constant-time / side-channel (constant-time-analysis / -testing)
Four patterns account for most timing leaks:
```c
if (secret == 1) { ... }   // 1. secret-dependent branch  → CRITICAL
lookup_table[secret];      // 2. secret-indexed array     → HIGH (cache timing)
data = secret / m;         // 3. variable-time division   → MEDIUM (CPU-dependent)
data = a << secret;        // 4. variable-time shift       → MEDIUM (CPU-dependent)
```
- Dangerous division instrs by arch: x86_64 `DIV/IDIV/DIVQ/IDIVQ`; ARM64 `UDIV/SDIV`;
  RISC-V `DIV/DIVU/REM/REMU`; PPC `DIVW/DIVD`. FP: `DIVSS/DIVSD/SQRTSS/SQRTSD`.
- **Constant-time fixes (compiled.md):**
  ```c
  // division → Barrett reduction (precompute mu = ceil(2^32/divisor))
  uint32_t q = (uint32_t)(((uint64_t)a * mu) >> 32);
  // branch → constant-time select
  uint32_t mask = -(uint32_t)(secret != 0);
  result = (a & mask) | (b & ~mask);
  // compare → CRYPTO_memcmp / subtle.ConstantTimeCompare
  ```
- Real impact: **KyberSlash (2023/24)** division leaked ML-KEM secret coefficients →
  key recovery; **Lucky Thirteen (2013)** CBC-padding timing → plaintext recovery;
  **Brumley–Boneh (2005)** Montgomery-reduction timing → remote RSA key extraction.

### Zeroization (zeroize-audit)
- Approved C/C++ wipes: `explicit_bzero`, `memset_s`, `SecureZeroMemory`,
  `OPENSSL_cleanse`, `sodium_memzero`, volatile wipe loop + barrier
  (`asm volatile("" ::: "memory")`). Plain `memset` is **not** approved — DSE removes it.
- Approved Rust: `zeroize::Zeroize`, `Zeroizing<T>`, `#[derive(ZeroizeOnDrop)]`.
- Hard evidence rules (non-negotiable): `OPTIMIZED_AWAY_ZEROIZE` requires an IR diff
  showing the wipe present at O0, absent at O1/O2 (`store volatile i8 0` count
  O0=N → O2=0 is classic DSE). `STACK_RETENTION`/`REGISTER_SPILL` require an
  assembly excerpt. Never source-only.
- Rust footguns (rust-zeroization-patterns): `#[derive(Copy)]` on a secret type =
  CRITICAL (bitwise dup, no Drop ever runs); `Vec<u8>` zeroize wipes `len` not
  `capacity` (tail readable) — use `Zeroizing` or `zeroize(); shrink_to_fit()`;
  `ManuallyDrop<T>` field never auto-drops; partial `Drop` that forgets a field.
- Secret name heuristics to scan: `key`, `secret`, `seed`, `priv`, `sk`,
  `shared_secret`, `nonce`, `token`, `pwd`, `pass`.

### Wycheproof differential testing (wycheproof)
- Test every `result`: **valid** (must pass), **invalid** (must fail), **acceptable**
  (allowed to pass; treat as a warning worth investigating). Only-valid testing
  misses the vulns where bad input is wrongly accepted.
- Vector files: `aes_gcm_test.json`, `chacha20_poly1305_test.json`,
  `ecdsa_*_test.json`, `eddsa`/`ed25519_test.json`, `ecdh_*_test.json`,
  `rsa_*_test.json` (prefer `testvectors_v1/`).
- Classes caught: signature malleability (EdDSA append/strip zeros — len check
  `if (sig.length !== 128) return false`), non-canonical DER (ECDSA first-bit
  `if ((data[p.place] & 128) !== 0) return false`, leading-zero length field),
  invalid-curve (ECDH), padding oracle (RSA-PKCS1), tag forgery (AEAD). Real CVEs:
  elliptic npm CVE-2024-42459/42460/42461.

### TLS posture (13-crypto-analysis)
- Versions: prefer TLS 1.3; TLS 1.2 minimum; refuse 1.0/1.1/SSLv3/SSLv2.
- TLS-1.2 ciphers: ECDHE + AEAD only; reject CBC, RC4, NULL, EXPORT, anonymous.
- CVE checklist: Heartbleed (CVE-2014-0160), POODLE (SSLv3), BEAST (TLS1.0+CBC),
  ROBOT (RSA kx), DROWN (SSLv2 anywhere on host), Logjam/FREAK (DHE<2048 / EXPORT),
  CRIME/BREACH (TLS compression), Sweet32 (3DES), weak cert (RSA<2048 / SHA-1 sig).
- Cert: `VERIFY_PEER`, full chain, hostname check on; pin high-trust links + backup
  pin; HSTS preload; OCSP stapling.

### PQC / crypto-agility (13-crypto-analysis v3)
- Finalized: FIPS 203 **ML-KEM** (kx), FIPS 204 **ML-DSA** (sig), FIPS 205
  **SLH-DSA** (hash-based sig). Recommend hybrid TLS group `X25519MLKEM768`.
- Prioritize PQC for long-lived secrets — **harvest-now-decrypt-later** is a
  present risk. RSA-2048 acceptable now but on the migration clock.

---

## Tools & commands

Only tools/flags actually named in the source skills.

```bash
# --- TLS scan (crypto-audit, 13-crypto-analysis) ---
testssl.sh https://target
testssl.sh --severity HIGH --quiet example.com
sslyze --regular target
sslyze --regular example.com --json_out result.json
openssl s_client -connect example.com:443 -tls1_2 2>/dev/null | grep -E "Protocol|Cipher"
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer
openssl dhparam -out /etc/nginx/dhparam.pem 4096
curl --tlsv1.3 --tls-max 1.3 https://target     # lower-bound TLS enforcement

# --- Constant-time static analyzer (constant-time-analysis) ---
uv run {baseDir}/ct_analyzer/analyzer.py <source_file>
uv run {baseDir}/ct_analyzer/analyzer.py --warnings <source_file>        # branch warnings
uv run {baseDir}/ct_analyzer/analyzer.py --func 'sign|verify|decrypt' <file>
uv run {baseDir}/ct_analyzer/analyzer.py --json <file>                   # CI / exit 1 = violations
uv run {baseDir}/ct_analyzer/analyzer.py --arch x86_64 crypto.c          # test EACH deploy arch
uv run {baseDir}/ct_analyzer/analyzer.py --arch arm64 crypto.c
uv run {baseDir}/ct_analyzer/analyzer.py --opt-level O0 crypto.c         # AND each opt level
uv run {baseDir}/ct_analyzer/analyzer.py --opt-level O3 crypto.c
#   langs: .c .cpp .go .rs .swift .java .kt .cs .php .js .ts .py .rb
#   --compiler gcc|clang|go|rustc ; --arch {x86_64,arm64,arm,riscv64,ppc64le,s390x,i386}

# --- Constant-time dynamic/statistical (constant-time-testing) ---
#   dudect: Welch's t-test, fixed-vs-random input classes (high |t| = leak)
timeout 600 ./ct_test
taskset -c 2 ./ct_test                # pin to isolated core, reduce OS noise
objdump -d ./binary                   # verify compiler didn't introduce branches
#   timecop: poison()/unpoison() secret memory, run under Valgrind
valgrind --leak-check=full --track-origins=yes ./binary

# --- Zeroize IR/ASM evidence (zeroize-audit) ---
{baseDir}/tools/emit_ir.sh  --src <f> --out <f>.O0.ll --opt O0 -- "${FLAGS[@]}"
{baseDir}/tools/emit_ir.sh  --src <f> --out <f>.O2.ll --opt O2 -- "${FLAGS[@]}"
{baseDir}/tools/diff_ir.sh  <f>.O0.ll <f>.O1.ll <f>.O2.ll   # non-zero exit = divergence
{baseDir}/tools/emit_asm.sh --src <f> --out <f>.O2.s --opt O2 -- "${FLAGS[@]}"
#   Rust: emit_rust_mir.sh / emit_rust_ir.sh / emit_rust_asm.sh (--opt, --crate, --bin/--lib)

# --- Wycheproof vectors (wycheproof) ---
git submodule add https://github.com/C2SP/wycheproof.git
#   raw fetch: https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/<file>.json
#   parse JSON → for each testGroup → for each test: assert by tv['result']
```

Mozilla-modern nginx TLS (13-crypto-analysis): `ssl_protocols TLSv1.2 TLSv1.3;`
ECDHE+AEAD cipher list, `ssl_session_tickets off;` (forward secrecy),
`ssl_stapling on;`, HSTS `max-age=63072000; includeSubDomains; preload`.

---

## Expert gotchas / bypasses

- **No data-flow in the CT analyzer (constant-time-analysis).** It flags *every*
  `DIV`/branch regardless of whether a secret is involved. Triage each:
  `int n = data_len / 16;` (length → false positive) vs
  `int32_t q = secret_coef / GAMMA2;` (private-key-derived → TRUE POSITIVE). Ask:
  is the operand a compile-time constant or public param (FP), or derived from /
  attacker-influenceable on a secret (TP)?
- **Test every (arch × opt-level).** A clean O2 build can emit a `DIV` at O0; ARM and
  x86 divide differently. One-config testing is the #1 CT mistake. `-O0` can *hide*
  a leak present at `-O3`, and vice-versa.
- **Static CT analysis can't see cache/microarch.** It's instruction-level only —
  no Spectre, no cache-timing from access patterns. Pair with dudect (statistical)
  + Timecop (dynamic). dudect gives no root cause; Timecop pinpoints the line but
  misses microarch.
- **"The compiler won't optimize my wipe away" is a rationalization (zeroize-audit).**
  Reject without IR/ASM proof. Also reject: "stack secrets auto-clean" (needs ASM
  proof of bytes at `ret`), "memset is sufficient" (DSE), "we only hold it briefly,"
  "this isn't a real secret." Retain the finding and log the attempted override.
- **GCM nonce reuse is catastrophic, not cosmetic.** Same (key, nonce) twice →
  plaintext XOR leak *and* authentication-key recovery → universal forgery. Treat as
  Critical even if "it almost never repeats."
- **Library defaults are footguns.** `Cipher.getInstance("AES")` and `AES.new(key)`
  silently select **ECB**; `crypto.createCipher` derives the IV from the key. Grep
  for the bare constructor, not just the string "ECB."
- **Signature bugs are usually omission, not weakness.** The exploit is "verification
  was never called" or "`alg` taken from the attacker's token," not a broken curve.
  Also watch type-coercion in sig paths (`parseInt → NaN`).
- **Wycheproof "acceptable" ≠ pass.** Don't ignore it — it flags non-ideal-but-legal
  inputs that often expose subtle bugs. Filter test groups by your real key/IV sizes
  to avoid drowning in unsupported-param noise, but never skip invalid/acceptable.
- **Signature malleability breaks consensus, not secrecy.** Two valid sigs for one
  message → divergent accept/reject across implementations (the elliptic-npm CVEs).
  The fix is an exact length / canonical-DER check, not a stronger algorithm.
- **Diagram before you attack a protocol (crypto-protocol-diagram).** Don't diagram
  from memory — memory inverts arrows and drops steps. When both spec and code exist,
  build the canonical spec diagram first, then annotate code divergences with `⚠️`
  (e.g. "spec requires MAC here — implementation omits it"). The missing MAC / absent
  abort path *is* the vulnerability.
- **Don't roll your own — and don't incrementally patch a broken design.** If the
  audit surfaces custom crypto or ROT13-as-protection, the recommendation is
  "replace, don't patch."
- **Crypto changes fail silently.** Always round-trip encrypt/decrypt post-fix; a
  KMS rollout that has encrypt IAM but not decrypt IAM bricks the data.

---

## Delegate to

- **crypto-audit** — full implementation review of algorithm/mode/KDF/IV/sig/TLS/key
  lifecycle. Use when reviewing how an app actually calls crypto (the subtle class).
- **13-crypto-analysis** — TLS/cipher-suite auditing, hash identification, PQC
  migration, Mozilla nginx config, `tls_auditor.py`. Use for TLS posture + PQC.
- **constant-time-analysis** — static assembly/bytecode scan for variable-time ops
  across 13 languages. Use when reviewing/writing secret-handling native code.
- **constant-time-testing** — dudect (statistical) + Timecop (dynamic) timing-leak
  detection and the 4-phase workflow. Use to confirm/locate a suspected timing leak.
- **zeroize-audit** — IR/ASM-evidenced detection of missing/optimized-away secret
  wipes in C/C++/Rust, with PoC generation. Use when keys/secrets live in native memory.
- **wycheproof** — differential test-vector validation against known attack classes.
  Use to test an AEAD/signature/KEX implementation for malleability/DER/curve bugs.
- **crypto-protocol-diagram** — extract message flow + crypto annotations into a
  Mermaid/ASCII sequence diagram from code, RFC, paper, or ProVerif/Tamarin. Use to
  model a handshake/MPC before attacking and to spot spec-vs-impl divergence.

### Cross-cluster references
- **owasp-audit** A02 (crypto baseline) + A07 (timing-safe compare) — obvious MD5 /
  VERIFY_NONE cases before this deeper pass.
- **secrets-audit** — key storage / hardcoded-secret discovery feeding the key inventory.
- **iam-audit** — KMS/HSM envelope-encryption and key-rotation patterns.
- **mobile-audit** (17) — CryptoKit/Tink, secure-storage, cert pinning on device.
- **web-pentest / api-audit** — JWT `alg:none`, webhook-signature, padding-oracle
  surfaces reached over HTTP.
- **mermaid-to-proverif** — formally verify a protocol after diagramming it.
