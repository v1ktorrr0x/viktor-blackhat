# Mobile Application Security Playbook

Android & iOS app security testing against OWASP **MASVS** (verification standard) and **MASTG** (testing guide). Covers static analysis of APK/IPA artifacts, dynamic instrumentation, secure-storage/transport review, IPC/deeplink abuse, and Firebase backend misconfiguration. Authorized testing only — defang any live payload before writing it down.

> **Authorization gate** (mobile-audit, 17-mobile-security): test only apps you own or have **written** scope for. Decompiling/repackaging a competitor app is fast legal exposure. Frida/objection/SSL-bypass are for *your* apps on *your* test device — not "test in production." Confirm scope before touching a binary. Refuse stalkerware/surveillance builds.

---

## When this applies

Route an engagement here when you see:

- An **APK / AAB** (Android) or **IPA** (iOS) artifact to review, or a request to "decompile / reverse / static-analyze a mobile app."
- Mentions of **MASVS / MASTG / OWASP Mobile Top 10**, "mobile pentest," "mobile audit."
- **Insecure storage** signals: `SharedPreferences`, `NSUserDefaults`, Keychain/Keystore, plist, hardcoded secrets in an app.
- **Transport** signals: certificate pinning, SSL bypass, App Transport Security, `network_security_config.xml`, cleartext traffic.
- **Platform** signals: `AndroidManifest.xml`, exported components, deep links / URL schemes / App Links, `Info.plist`, `addJavascriptInterface`.
- **Frida / objection** dynamic instrumentation, root/jailbreak detection bypass, anti-tamper.
- A **Firebase** backend behind the app (`firebaseio.com`, `appspot.com`, `AIza…` keys, `google-services.json`) → see the Firebase section.
- Suspicious/packed APK triage (banking-trojan markers, accessibility abuse) → hand deeper RE to malware/RE specialists.

Pair-with: backend API flaws → `api-audit` / web-security (09); dependency CVEs (CocoaPods/SPM/Gradle) → `dependency-audit`; native `.so` RE → reverse-engineering (04); packed/malicious APK → malware-analysis (05); custom crypto → crypto-analysis (13).

---

## Methodology

**Phase 0 — Scope & profile.** Confirm written authorization and a controlled test device/emulator. Set the MASVS profile: **L1** (standard), **L2** (defense-in-depth / sensitive data), **R** (resilience required — only banking/DRM/gov). For most apps, do **not** waste effort on RESILIENCE; ship secure crypto + a proper backend (mobile-audit).

**Phase 1 — Unpack & map (static).**
1. **Android:** `apktool d app.apk -o app_decompiled` to get `AndroidManifest.xml`, `classes*.dex`, `resources.arsc`, `lib/`, assets. Decompile to Java with `jadx app.apk` (or `d2j-dex2jar` + `jd-gui`). Fingerprint packers/obfuscators/compiler with `apkid`.
2. **iOS:** `unzip app.ipa`; locate `Payload/<App>.app/`. Read `Info.plist` (`plutil -p`), enumerate classes with `class-dump`, inspect link/binary with `otool`.
3. Run the automated first-pass triage: `python scripts/apk_analyzer.py --apk app.apk --sources ./jadx_out` (17-mobile-security) — dumps package/version, dangerous permissions, manifest flags, exported components, and regex secret hits in one shot.

**Phase 2 — Manifest / plist review.** Flag debuggable/backup, cleartext traffic, exported components without permissions, deep-link autoVerify, ATS exceptions, URL schemes, dangerous permissions (see checklist).

**Phase 3 — Secret & storage hunt.** `strings` the binary first; then grep decompiled sources/resources/assets for keys, tokens, endpoints, hardcoded crypto keys/IVs. Map every sink where sensitive data lands at rest (prefs, SQLite, plist, Keychain/Keystore, logs, WebView cache, clipboard, backups, app-switcher snapshots).

**Phase 4 — Install & instrument (dynamic).** Install on rooted/jailbroken test device or emulator. Proxy traffic (Burp/mitmproxy); bypass pinning with objection/Frida *only to observe your own app's traffic*. Hook crypto/auth/root-detection. Watch logcat / filesystem for leakage during use.

**Phase 5 — Exercise attack surface.** Fire exported components, deep links, and intents from `adb`/`simctl`. Test session handling (background→resume blur, force-quit→relaunch auto-login). Replay/modify API requests for IDOR/BFLA/mass-assignment (→ api-audit).

**Phase 6 — Backend misconfig.** If Firebase is in play, extract config and test Auth/RTDB/Firestore/Storage/Functions/Remote-Config (Firebase section). Clean up any test data you create.

**Phase 7 — Verify & report.** Each finding gets a MASVS-ID, severity, file/location evidence, impact, remediation, and a verification step. Cross-link backend findings to api-audit output.

---

## High-signal checklist

### MASVS-STORAGE (sensitive data at rest)
- **iOS Keychain accessibility:** strongest class only — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` / `…AfterFirstUnlockThisDeviceOnly`. Flag `kSecAttrAccessibleAlways` and non-`ThisDeviceOnly` variants (mobile-audit, 17).
- No secrets in `NSUserDefaults`, plist, or app bundle — `strings <app>` must not reveal API keys/tokens.
- **Android:** secrets in `EncryptedSharedPreferences` / Keystore-backed storage, **not** raw `SharedPreferences`. Verify keys are Keystore-backed (`KeyGenParameterSpec`), not app-derived.
- **Android backup:** `android:allowBackup="false"` (or tightly scoped backup rules) — else `adb backup -f backup.ab com.package.name` → `abe.jar unpack` extracts everything.
- No PII/tokens in logs that survive a crash (`NSLog`, `Log.d`, third-party crash reporters).
- Clipboard: sensitive fields don't auto-share — iOS `pasteboard.expirationDate`, Android `ClipDescription.EXTRA_IS_SENSITIVE`.
- App-switcher snapshot doesn't capture sensitive screens — iOS `applicationDidEnterBackground` blur, Android `FLAG_SECURE`.
- Live data extraction (on test device): inspect `/data/data/<pkg>/shared_prefs/*.xml`, `…/databases/*.db` (`sqlite3 → .tables`), `…/files/`; iOS `/var/mobile/Containers/Data/Application/<UUID>/{Documents,Library/Preferences,Library/Caches,tmp}` (mobile-pentesting).

### MASVS-CRYPTO
- No hardcoded keys — `strings`/`class-dump`/`apktool` reveal embedded constants. Secret regexes (apk_analyzer.py): Google API key `AIza[0-9A-Za-z\-_]{35}`, AWS `AKIA[0-9A-Z]{16}`, private-key block `-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`, JWT `eyJ[A-Za-z0-9_\-]{10,}\.[…]\.[…]`, Firebase URL `https://[a-z0-9\-]+\.firebaseio\.com`, kw `(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*["'][^"']{6,}["']`.
- Modern algorithms only — AES-GCM, ChaCha20-Poly1305. **Reject** AES-ECB, DES, RC4, MD5, SHA-1.
- CSPRNG: `SecRandomCopyBytes` (iOS) / `SecureRandom` (Android). Never `Math.random()`; never `arc4random()` for crypto material.
- KDF: PBKDF2 ≥ **600,000** iterations (OWASP 2024) or Argon2id.
- **IV/nonce reuse** — `iv = "0000000000000000"` is worse than no encryption (leaks plaintext patterns). CWE-329/CWE-330.
- Flag any roll-your-own crypto; bias to libsodium / Tink. Deep dive → crypto-analysis (13).

### MASVS-NETWORK
- **iOS ATS:** no global `NSAllowsArbitraryLoads = true` in `Info.plist`; any exception is per-domain, justified, documented.
- **Android:** `network_security_config.xml` present and enforcing `<base-config cleartextTrafficPermitted="false">`; manifest has no `usesCleartextTraffic="true"`.
- **Pinning** for high-trust backends — prefer public-key pinning (survives cert rotation) via `<pin-set>` / OkHttp `CertificatePinner` (Android) or `URLSessionDelegate` + `URLAuthenticationChallenge` (iOS). **Require a backup pin** — single-cert pinning bricks the app on rotation.
- WebView: `WKWebView` only on iOS (never `UIWebView`); audit the JS bridge; `setJavaScriptEnabled(false)` when JS isn't needed.
- `loadUrl` with user-controlled URL → open redirect / intent-spoof / phishing surface.

### MASVS-AUTH
- Biometric via `LAContext.evaluatePolicy` (iOS) / `BiometricPrompt` (Android) — not deprecated `FingerprintManager`.
- Biometric bound to Keychain/Keystore access (`SecAccessControl.biometryAny`, Android `setUserAuthenticationRequired(true)`) — not a bare UI boolean check (which Frida flips trivially).
- Session/refresh tokens in Keychain/Keystore; short-lived access token + server-revocable refresh token.
- OAuth in the platform browser — `ASWebAuthenticationSession` (iOS) / Custom Tabs (Android), **never** a WebView (steals creds).

### MASVS-PLATFORM (IPC / deeplinks)
- Every `android:exported="true"` component reviewed for parameter handling. Exported `ContentProvider` → `android:exported="false"` unless cross-app is intended; validate every URI path if exported.
- Exported services need `android:permission`; otherwise any app can call them. In-app broadcasts use `LocalBroadcastManager`.
- Universal Links (iOS) / App Links (Android) use HTTPS + verified domain (`android:autoVerify`) — not custom schemes (`myapp://`, which any app can register). App-link autoVerify present → check for **app-link hijack**.
- Deeplinks that trigger sensitive actions (purchase, account change) require in-app confirmation. WebView→`myapp://` action without consent = XSS-to-action chain.
- iOS: URL-scheme handler validates source app (`UIApplicationOpenURLOptionsSourceApplicationKey`); app groups / Keychain access groups scoped to your own bundles only.
- Test it: `adb shell am start -a android.intent.action.VIEW -d "app://open?param=value"`; `adb shell am start -n com.pkg/.Activity --es key malicious_value`; `adb shell am startservice …`; `adb shell am broadcast -a com.pkg.ACTION`; iOS `xcrun simctl openurl booted "app://…"` (mobile-pentesting).

### MASVS-CODE
- Native libs: PIE + stack canaries enabled (`otool -hv` iOS, `readelf -h` on `.so`); symbols stripped (ProGuard/R8, `strip`).
- No debug build in prod (`android:debuggable`, `DEBUG`). Verify signing scheme v1/v2/v3 and reject debug certs.

### MASVS-RESILIENCE (R-profile only)
- Root/jailbreak detection, anti-debug (`ptrace` self-attach / `Debug.isDebuggerConnected`), obfuscation (DexGuard/Arxan for high-value; R8 baseline), integrity checks. Pin SSL in **native** code so a Kotlin/Swift-layer Frida hook can't disable it.
- Reality check (mobile-audit): every resilience control has a public bypass and falls to an attacker with physical access. They buy time, they don't prevent — don't over-invest.

### Malware triage markers (17-mobile-security)
- `apkid` packing; requested permissions vs. stated function; **accessibility-service abuse**; SMS/dialer/overlay permissions (`SYSTEM_ALERT_WINDOW`) = banking-trojan markers; C2 URLs in strings; dynamic code loading (`DexClassLoader`/`DexogClassLoader`). Hand confirmed IOCs → threat-hunting (06); deeper RE → 04/05.
- Dangerous permissions the triage script flags: `READ_SMS`/`SEND_SMS`/`RECEIVE_SMS`, `READ_CONTACTS`, `RECORD_AUDIO`, `CAMERA`, `ACCESS_FINE_LOCATION`, `READ_CALL_LOG`, `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`, `BIND_ACCESSIBILITY_SERVICE`, `READ_PHONE_STATE`, `QUERY_ALL_PACKAGES`.

---

## Firebase backend misconfig (firebase-apk-scanner)

Extract config from the APK, then test endpoints. Key format: `AIza[A-Za-z0-9_-]{35}`. Extraction locations: `google-services.json` → `client[].api_key[].current_key`; `res/values/strings.xml` → `google_api_key`/`firebase_api_key`; `assets/*.json`; smali `const-string "AIza"`; raw DEX strings.

```bash
apktool d -f -o ./decompiled app.apk
grep -r "firebaseio.com\|appspot.com\|AIza" ./decompiled/res/ ./decompiled/assets/
```

With PROJECT_ID + API_KEY, test (defanged — replace placeholders, clean up test data):

- **Open signup (CRITICAL):** POST `accounts:signUp` with email/password+`returnSecureToken` to `identitytoolkit.googleapis.com/v1/`. Account creation works even when the UI hides registration. Secure = success returns `ADMIN_ONLY_OPERATION`.
- **Anonymous auth (HIGH):** same endpoint, body `{"returnSecureToken":true}`. A returned `idToken` bypasses `auth != null` rules — then reuse it: `…firebaseio.com/users.json?auth=<token>`. "Just anonymous" is **not** a pass.
- **Email enumeration (MEDIUM):** `accounts:createAuthUri` — a varying `registered` field leaks account existence + `signinMethods`.
- **RTDB read (CRITICAL):** `curl https://PROJECT.firebaseio.com/.json`; structure via `?shallow=true`; enumerate `users`/`messages`/`orders`/`config`/`admin`.
- **RTDB write (CRITICAL):** `PUT …/_security_test.json` with junk; if it lands, test role overwrite `…/users/<uid>/profile.json {"role":"admin"}`. Delete your test node after.
- **Firestore (CRITICAL):** `…/v1/projects/PROJECT/databases/(default)/documents` lists collections; enumerate `users,accounts,orders,payments,messages,config,admin,secrets,tokens,api_keys,sessions,credentials`.
- **Storage listing (HIGH) / upload (CRITICAL):** `…firebasestorage.googleapis.com/v0/b/PROJECT.appspot.com/o` lists files (look for `.sql`/`.pdf`/`.env`/backups); test unauth upload (`uploadType=media&name=…`). Try both `.appspot.com` and raw bucket name.
- **Cloud Functions (MED-HIGH):** enumerate names from APK strings (`login,createUser,processPayment,webhook,admin,debug,…`); response codes — 404=absent, 401/403=exists+protected, 200=accessible. Test callable with `{"data":{}}`. **Try all regions:** `us-central1, us-east1/4, us-west1, europe-west1/2/3, asia-east1/2, asia-northeast1, asia-south1`.
- **Remote Config (MEDIUM):** `curl -H "x-goog-api-key: API_KEY" …firebaseremoteconfig.googleapis.com/v1/projects/PROJECT/remoteConfig` — often leaks internal endpoints, feature flags, and `sk_live_…`-style secrets.
- **Rule anti-patterns:** trusting client-set `isAdmin`; missing `.validate`/field validation; overly-broad `match /{document=**}`; client-timestamp time rules. Secure rules pull admin status from a trusted doc via `get(…)`.
- **API-key hardening:** restrict Android key to app SHA-1, iOS key to bundle ID; never ship server/admin keys client-side. A "public" API key never justifies open rules.

> **Reject these rationalizations** (firebase-apk-scanner): "read-only DB so it's fine" / "just anonymous auth" / "API key is public anyway" / "no sensitive data in there" / "it's internal" / "we'll fix before launch." Each is a documented finding regardless.

---

## Tools & commands

| Tool | Platform | Use |
|---|---|---|
| `apktool d app.apk -o out` / `b out -o mod.apk` | Android | Decode/rebuild; edit `out/smali/` |
| `jadx app.apk` | Android | DEX → Java decompiler |
| `d2j-dex2jar` + `jd-gui` | Android | DEX→JAR, browse JAR |
| `apkid` | Android | Packer/obfuscator/compiler fingerprint |
| `adb` | Android | `devices`, `connect ip:5555`, `install`, `shell pm list packages \| grep`, `pm path`, `pull base.apk`, `am start/startservice/broadcast`, `logcat`, `dumpsys package <pkg>` |
| `apk_analyzer.py --apk … --sources jadx_out --output report.json` | Android | Automated manifest/permission/exported/secret triage |
| backup: `adb backup -f backup.ab com.pkg` → `java -jar abe.jar unpack` | Android | Backup exfil test |
| repackage: `apktool b` → `jarsigner`/`uber-apk-signer` → `adb install` | Android | Smali-patch + resign test build |
| `unzip app.ipa`; `otool -L/-hv/-I`; `class-dump`; `plutil -p`; `strings` | iOS | IPA unpack & binary/header inspection |
| `frida-ios-dump -u App` | iOS | Decrypt App Store binary (jailbroken) |
| `frida` / `frida-ps -U`(`-Ua` iOS) | Both | Runtime hooking; `-f com.pkg -l script.js` |
| `objection -g com.pkg explore` | Both | `android/ios sslpinning disable`, `root/jailbreak disable`, `keychain dump`, `nsuserdefaults get`, `hooking list classes` |
| Burp Suite / mitmproxy | Both | Proxy; Android: `adb shell settings put global http_proxy ip:8080` then `…:0` to clear |
| MobSF | Both | Automated static+dynamic first-pass |
| semgrep / nuclei (mobile rules), Drozer | Both/Android | AST rules, pattern scan, Android IPC framework |
| Hopper / Ghidra / IDA | iOS/native | Disassemble Mach-O / `.so` |

Binary hardening checks (mobile-pentesting): PIE `otool -hv App | grep PIE`; stack canaries `otool -I App | grep stack_chk`; ARC `otool -I App | grep objc_release`.

---

## Expert gotchas / bypasses

- **Pinning bypass to see traffic, not to defeat the control.** objection `sslpinning disable` / a Frida `X509TrustManager.checkServerTrusted` + `SSLContext.init` no-op handles most Android stacks — but a finding is about *whether the backend trusts the bypassed client*, so always re-test API authz (IDOR/BFLA) once you're inside the channel. The pinning bypass itself is not the deliverable.
- **Anonymous Firebase tokens are real users.** `auth != null` rules pass for them. The single highest-yield, lowest-effort Firebase finding is anon-token → authenticated-resource access — test it every time even when "auth is required."
- **Shallow RTDB query leaks structure even when full read is denied** — `?shallow=true` maps the tree so you know which paths to target.
- **Exported `true` is implicit when an intent-filter is present** (pre-API-31) even without `android:exported`. Don't trust the absence of the attribute; enumerate filters too.
- **App Links `autoVerify` ≠ verified.** If the `/.well-known/assetlinks.json` association is broken/missing, the link is hijackable by another app claiming the host.
- **`addJavascriptInterface` + WebView loading untrusted content = RCE.** Combined with `loadUrl(user_input)` it's a direct bridge from web content to native methods.
- **Biometric as a UI check vs. a key gate.** If biometric success merely returns a boolean (not unlocking a Keystore/Keychain-protected key), Frida flips it in one line — bind auth to the key.
- **Resilience is a time tax, not a wall** (mobile-audit). Don't write up "root detection missing" as High on an L1 app; rank it by what data it actually protects. Conversely, don't let resilience theater hide a plaintext token in `SharedPreferences`.
- **Repackage to break client-side checks.** `apktool b` + smali edit + resign defeats most client-enforced logic (feature gates, debug flags) — proves the control belongs server-side.
- **`strings` the binary before you decompile.** Fastest path to secrets, backend URLs, debug endpoints, and Firebase project IDs; the apk_analyzer regexes catch the high-value ones automatically.
- **Test all Cloud Function regions.** A function returning 404 in `us-central1` may be live in `europe-west1` — region enumeration is the difference between "no functions found" and full enumeration.
- **Clean up.** Any RTDB/Storage/account test artifact you create is your responsibility to delete; the firebase scanner removes its own test entries by design.

---

## Delegate to

- **mobile-audit** — use when you need the full MASVS-category audit (STORAGE/CRYPTO/NETWORK/AUTH/PLATFORM/CODE/RESILIENCE) with profile-aware severity and a structured findings report; strongest on iOS Keychain accessibility classes and pinning-with-backup-pin nuance.
- **17-mobile-security** (Mobile Application Security) — use for the automated APK static first-pass (`apk_analyzer.py`), MASTG-test-mapped output, and suspicious/packed-APK malware triage with the dangerous-permission and banking-trojan marker set.
- **mobile-pentesting** — use for hands-on command-level dynamic work: adb/objection/Frida invocations, traffic interception setup, smali repackage+resign, iOS jailbreak/SSH filesystem access, and binary-hardening `otool` checks.
- **firebase-apk-scanner** — use (slash-invoke with an APK path) to auto-extract Firebase config and test Auth/RTDB/Firestore/Storage/Functions/Remote-Config end-to-end with severity-classified output. `disable-model-invocation` — invoke explicitly.
- Cross-cluster: **api-audit / web-security (09)** for backend IDOR/BFLA/mass-assignment once you're past pinning; **dependency-audit** for SDK CVEs; **reverse-engineering (04)** for `.so`/obfuscated logic; **malware-analysis (05)** for packed/malicious APKs; **crypto-analysis (13)** for custom crypto; **threat-hunting (06)** for C2/IOC correlation.
