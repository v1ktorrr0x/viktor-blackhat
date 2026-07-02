# Supply Chain, Dependencies & Secrets Playbook

Authorized security testing only. Findings here are remediation-oriented: rotate, pin, patch, prevent. Never weaponize a leaked credential or exploit a found CVE against a target you are not authorized to test.

## When this applies

Route an engagement here when the target shows any of these signals:

- A package manifest / lockfile exists: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`, `Gemfile.lock`, `go.mod`/`go.sum`, `Cargo.toml`/`Cargo.lock`, `pom.xml`, `build.gradle`, `composer.lock`, `*.csproj`.
- The user mentions: dependency audit, npm audit, CVE, vulnerable packages, supply chain, outdated deps, security advisory, secrets audit, leaked credentials, API key in code, gitleaks, trufflehog, git history scan, rotation policy, SBOM, VEX.
- You need a pre-engagement scoping pass over a project's dependency attack surface (which deps could be taken over or are unmaintained).
- A CI/CD pipeline, Dockerfile, or IaC config is in scope (build-time secret exposure + supply chain ingress).

Hand-off boundaries: runtime config/server hardening (nginx/sshd) overlaps with `02-vulnerability-scanner`; in-source SQLi/XSS/access-control belongs to `owasp-audit`; IAM/workload-identity belongs to `iam-audit`; container runtime to `container-audit`.

---

## Methodology

### Phase 1 — Inventory the full stack (map)

1. **Catalog every manifest, not just the root.** In monorepos read every `packages/*/package.json` and `apps/*/package.json`. (dependency-audit)
2. **Record framework + runtime + tool versions:** framework (Next.js, Django, Rails, Spring, Laravel, Express), language runtime (`engines` field — older-than-LTS Node makes other audits moot), Docker base images, Terraform providers, K8s version. (dependency-audit)
3. **Flag the manifest edge cases** that default audits miss: `optionalDependencies` (installed, not audited), `peerDependencies` (range may not match installed), `overrides`/`resolutions`/pnpm `overrides` (check whether used to *silence* an advisory rather than fix it). (dependency-audit)
4. **Confirm a lockfile is committed and used.** `git ls-files | grep -E 'package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|composer\.lock|Cargo\.lock|go\.sum'`. (dependency-audit)

### Phase 2 — Run automated CVE audits (test)

5. **Run the ecosystem-native audit tool** (see Tools table). For npm, run both full and production-only and **diff them** — vulns only in dev/build tooling do not ship to users and triage lower. (dependency-audit)
6. **Query OSV for ecosystem-precise advisories** in addition to NVD — OSV covers PyPI, npm, Go, crates, Maven, RubyGems, Packagist with exact version matching. (02-vulnerability-scanner)
7. **Cross-reference each direct dep's installed version** against the GitHub Advisory DB and the repo's own `/security/advisories`. Do not trust an LLM's hardcoded CVE list — advisory data rots; do a fresh check. (dependency-audit)

### Phase 3 — Prioritize by exploitability, not raw CVSS (verify)

8. **Combine `CVSS severity × EPSS exploit-probability × CISA KEV membership`.** A medium-CVSS CVE in the KEV catalog or with high EPSS outranks a high-CVSS CVE with no exploitation signal. State patch-first order on this combined basis. (02-vulnerability-scanner v3.0)
9. **Do reachability analysis** to cut transitive false positives: is the vulnerable function actually called? Use call-graph/import reachability; `npm ls <pkg>` + reading the parent's source can rule a path unreachable. Tag every finding `runtime` / `build-only` / `dev-only`. (dependency-audit, 02-vulnerability-scanner)
10. **Emit an SBOM + VEX:** generate CycloneDX/SPDX, then mark each CVE `affected` / `not_affected` / `fixed` so downstream consumers know what is actually reachable. (02-vulnerability-scanner v3.0)

### Phase 4 — Supply-chain risk + takeover surface

11. **Score each direct dependency against the takeover risk criteria** (single/anonymous maintainer, unmaintained/archived, low popularity, high-risk features like FFI/deser/code-exec, past critical CVEs, no SECURITY.md contact). Only report deps with at least one risk factor; absence from the report means low-risk. (supply-chain-risk-auditor)
12. **Check dependency-confusion / typosquat / malicious-package indicators** (Phase 5 checklist below).

### Phase 5 — Secret hunting (two halves: leaks + posture)

13. **Sweep for provider key prefixes first** — lowest false-positive, almost always real. Scope to tracked files with `git ls-files` to skip `node_modules`. (secrets-audit)
14. **Scan git history, not just the working tree** — a deleted secret still lives in `git log -p`, every fork, and every clone. (secrets-audit)
15. **Check the forgotten places:** Docker image layers, CI logs, frontend bundles, crash reports, backups, public blob storage, docs. (secrets-audit)
16. **Triage each found secret:** verify-live → exposure window → blast radius → rotate (add-new-then-revoke-old) → audit provider logs for use → clean source → history-rewrite last. Rotate first, rewrite second; treat any leaked secret as compromised regardless. (secrets-audit)
17. **Audit the secrets-management posture** against the storage hierarchy and the runtime-fetch / scoped-IAM / rotation / cross-env-isolation checklist. (secrets-audit)

---

## High-signal checklist

### Provider key prefix grep patterns (run first; low FP)

Defanged note: these are detection regexes, not live keys. (secrets-audit)

```bash
# Stripe
grep -rE "(sk_live_|sk_test_|rk_live_|whsec_)[A-Za-z0-9]{20,}" . \
  --include="*.{js,ts,jsx,tsx,py,rb,go,java,php,sh,env,yml,yaml,json}"

# AWS access key IDs
grep -rE "(AKIA|ASIA)[A-Z0-9]{16}" .

# AWS secret keys (40-char base64-ish) — HIGH FP, scope to env/json only
grep -rE "[A-Za-z0-9/+=]{40}" . --include="*.env*" --include="*.json"

# GitHub tokens (ghp_ / gho_ / ghu_ / ghs_ / ghr_)
grep -rE "gh[pousr]_[A-Za-z0-9]{36}" .

# Google Cloud API key + service-account JSON
grep -rE "AIza[A-Za-z0-9_-]{35}" .
grep -rln '"type": "service_account"' . --include="*.json"

# Slack
grep -rE "xox[baprs]-[A-Za-z0-9-]+" .

# OpenAI / Anthropic
grep -rE "sk-[A-Za-z0-9]{32,}" .
grep -rE "sk-ant-[A-Za-z0-9_-]{90,}" .

# Generic high-entropy assignment in env files
grep -rE "^[A-Z_]+=[A-Za-z0-9/+=]{32,}$" . --include="*.env*"

# Scoped sweep over tracked files only (avoids node_modules noise)
git ls-files | xargs grep -lE 'sk_live_|ghp_|AKIA[A-Z0-9]{16}|sk-ant-|AIza[A-Za-z0-9_-]{35}' 2>/dev/null
```

### Git history secret patterns (secrets-audit)

```bash
git log -p -S "sk_live_" --all            # every commit touching the pattern
git log -p --all | grep -E "^-.*sk_live_" # only deleted lines
trufflehog git file://. --since-commit=<first-commit>
# Destructive cleanup — rotate first, coordinate re-clone, every fork still exposed:
git filter-repo --invert-paths --path config/secrets.yml
bfg --delete-files secrets.yml
```

### Secret storage hierarchy (worst → best) (secrets-audit)

- Hardcoded in source / image / shared docs — **never acceptable**.
- `.env` in repo (even gitignored — leaks via push/backup/archive) — bootstrap only, always flag.
- Env vars only — ok ephemeral dev; weak for prod (visible in `/proc`, crash dumps, logs).
- Secrets manager pulled at deploy time — standard.
- Workload identity federation (no stored secret) — best where supported.

### Secrets-management posture checks (secrets-audit)

- No secrets in git history (`gitleaks --all`).
- `.gitignore` covers `.env*` (care for `.env.example`); no `.env` committed.
- Secrets fetched at runtime, not baked at build (rotation without image rebuild).
- IAM scoped per-secret (service A reads secret A, not B).
- Rotation defined per class (admin ~30d, service ~90d) **and automated** — manual scripts drift.
- Every Get/Decrypt access logged.
- Cross-environment isolation: staging can never read prod secrets (different KMS keys + IAM).
- Break-glass procedure exists when the secrets manager is down.

### Supply-chain attack indicators (dependency-audit)

- **Dependency confusion:** private package names claimable on a public registry; missing `.npmrc`/`pip.conf` scoping to the private registry; no lockfile integrity verification.
- **Typosquatting:** close-misspelling names, recently published packages with very few downloads, recent ownership changes.
- **Malicious package:** `scripts.postinstall` making network requests or executing code; obfuscated code; permissions exceeding functionality. (Inspect, do not execute, untrusted postinstall hooks.)
- **Lockfile integrity in CI:** `npm install` (bad) vs `npm ci` (good); `yarn install` (bad) vs `yarn install --immutable` (good); `pip install -r` (bad) vs `pip install --require-hashes -r` (good). Check `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `vercel.json`, `netlify.toml`, `Dockerfile`.

### Dependency takeover risk criteria (supply-chain-risk-auditor)

Flag a direct dependency high-risk if it has any of:

- **Single / anonymous maintainer** — one person can be phished/bribed into pushing malicious code (the left-pad lesson). Risk lessened for prolific known maintainers (e.g. `sindresorhus`), greatly increased if the GitHub identity is not tied to a real-world identity.
- **Unmaintained** — stale, archived, deprecated, or large backlog of unaddressed bug/security issues (feature requests do not count).
- **Low popularity** — few stars/downloads relative to peers → fewer eyes on malicious changes.
- **High-risk features** — FFI, deserialization, third-party code execution.
- **Past high/critical CVEs** disproportionate to popularity/complexity.
- **No security contact** in `.github/SECURITY.md`, `CONTRIBUTING.md`, `README.md`, or project site.

For each flagged dep, supply a more-popular/better-maintained drop-in **Suggested Alternative** (prefer direct successors). Use `gh` to get exact star/issue counts; round with `~` notation. Verify `gh` is installed first.

### CI/CD + IaC supply-chain ingress (dependency-audit)

- **GitHub Actions:** `pull_request_target` with checkout of PR code (code-injection); secrets reachable in forked-PR workflows; unpinned actions (`uses: actions/checkout@main` vs `@v4.1.0` or SHA pin); script injection via `${{ github.event.issue.title }}` in `run:` blocks.
- **Docker:** running as root (missing `USER`); base image with known CVEs; secrets baked into layers (`docker history`, `--build-arg SECRET=...`); `latest` tag instead of pinned digest.
- **Terraform/IaC:** hardcoded secrets in `.tf`; unpinned provider versions; missing state encryption; over-permissive provider IAM.

### Build-time secret leak surface (secrets-audit)

- Build args used for secrets — `--build-arg AWS_SECRET=...` lands in image history; use BuildKit `--secret` instead.
- `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` env vars ship to the browser — grep the bundled JS.
- Logging frameworks (Sentry/Datadog/Bugsnag) dumping `process.env` on unhandled exception — scrub config required.
- K8s `Secret` without etcd encryption — base64 is encoding, not encryption.
- OAuth client secrets embedded in mobile/public clients — PKCE is the answer.

### Framework evergreen anti-patterns worth a grep (dependency-audit)

- **Next.js:** middleware auth bypass (note CVE-2025-29927 class), `dangerouslySetInnerHTML` without sanitization, `next/image` SSRF via unrestricted domains, `NEXT_PUBLIC_` secret leak. Server-only modules touching `process.env.[A-Z_]+` should `import "server-only";` — grep `lib/` files that read env but do not import it; inverse: a `"use client"` file importing such a module is a leak.
- **Serverless/edge:** module-scoped `new Map()`/`new Set()` used as a rate limiter is per-instance and trivially bypassed — grep `const rateLimitMap = new Map`, `const cache = new Map` in server-action/API-route files; fix with a shared store (Redis/Upstash/KV). `x-forwarded-for` is attacker-spoofable behind a misconfigured proxy chain.
- **Django:** `DEBUG=True` in prod, wildcard `ALLOWED_HOSTS`, `@csrf_exempt`, raw SQL via `extra()`/`raw()`/`RawSQL`, pickle session serializer, secret key in source.
- **Spring/Java:** Spring4Shell-class RCE, Jackson polymorphic deser, SpEL injection, Actuator endpoints exposed unauthenticated.
- **Laravel/PHP:** `APP_DEBUG=true` leaking env in error pages, mass assignment without `$fillable`/`$guarded`, unvalidated file upload enabling PHP execution.

---

## Tools & commands

Only tools/flags named in the source skills.

| Ecosystem | Audit command | Source |
|---|---|---|
| Node.js | `npm audit --json`; `npm audit --omit=dev --json` (diff the two) | dependency-audit |
| Node.js fix | `npm audit fix`; `npm audit fix --dry-run --force` (always dry-run first) | dependency-audit |
| Node reachability | `npm ls <package>`; `npm ls --omit=dev <package>` | dependency-audit |
| Python | `pip audit`; `safety check` | dependency-audit |
| Ruby | `bundle audit` | dependency-audit |
| Go | `govulncheck ./...` | dependency-audit |
| Rust | `cargo audit` | dependency-audit |
| PHP | `composer audit` | dependency-audit |
| .NET | `dotnet list package --vulnerable` | dependency-audit |
| Container/FS | `docker scout cves <image>`; `trivy image <image>`; `trivy fs .` | dependency-audit |
| Secret scan | `gitleaks detect` (low FP, pre-commit + CI); `trufflehog git file://.` (verifies against live API); `detect-secrets scan` (baseline workflow) | secrets-audit |
| Platform secret scan | GitHub Secret Scanning + Push Protection; GitLab Secret Detection | secrets-audit |
| Supply-chain metadata | `gh` CLI for exact star/issue/release counts | supply-chain-risk-auditor |
| Network vuln | `nmap -sV --script vuln -p ...`; `nmap -p 445 --script smb-vuln*`; `nmap -p 443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle` | 02-vulnerability-scanner |
| Template scan | `nuclei`; `trivy`; `openvas` | 02-vulnerability-scanner |

OSV query (the audit script posts directly to `https://api.osv.dev/v1/query`) (02-vulnerability-scanner `dependency_auditor.py`):

```json
{ "version": "<version>", "package": { "name": "<pkg>", "ecosystem": "npm|PyPI|Go|crates.io|RubyGems|Packagist|Maven" } }
```

Helper scripts shipped with 02-vulnerability-scanner (paths under that skill dir):

```bash
python scripts/dependency_auditor.py --project-dir ./app --format json --output audit.json
python scripts/dependency_auditor.py --requirements requirements.txt --severity high,critical
python scripts/cvss_calculator.py --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
python scripts/config_auditor.py --type sshd --config /etc/ssh/sshd_config
```

CVSS v3.1 severity bands: 0.0 None · 0.1–3.9 Low · 4.0–6.9 Medium · 7.0–8.9 High · 9.0–10.0 Critical. Example vectors: remote unauth RCE `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0; local privesc `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = 7.8. (02-vulnerability-scanner)

---

## Expert gotchas / bypasses

- **`npm audit fix --force` can "fix" by downgrading.** It may resolve an advisory by installing an *older* package version that lacks the audit signature (e.g. `next@16` → `next@9` to dodge a transitive postcss CVE). Read the dry-run for "Will install X@Y, which is a breaking change" — that is the tool trying to downgrade. Almost always wrong. (dependency-audit)
- **`overrides`/`resolutions` used to silence, not fix.** Check whether an override pins to a *patched* version or just to one that dodges the advisory signature while staying vulnerable. (dependency-audit)
- **Dev/build-only vulns should not block a release** but novices report them at full severity. Diff `npm audit` vs `npm audit --omit=dev` and confirm runtime reachability before escalating. (dependency-audit)
- **When `npm audit fix` cannot resolve** (transitive dep pinned upstream): determine reachability → try an `overrides` pin to a patched version (test, can break parent) → swap the parent provider → if none apply, document explicitly and track upstream; never silently drop the finding. (dependency-audit)
- **Raw CVSS is the wrong sort key.** Prioritize on `CVSS × EPSS × KEV`. A KEV-listed medium beats a non-exploited high. (02-vulnerability-scanner v3.0)
- **Rotate before history-rewrite.** Rewriting git history is destructive (every dev re-clones, every fork is still exposed) and pointless before rotation — the secret is compromised the moment it's committed. Add-new-then-revoke-old to avoid breaking prod. (secrets-audit)
- **Verify a secret is live with a minimal call only** (`aws sts get-caller-identity`, `stripe balance retrieve`, account-info `curl`). Never pivot, extract data, or weaponize. Some leaked keys are already revoked or sandbox-only. (secrets-audit)
- **The AWS-secret-key 40-char regex has a high false-positive rate** — scope it to `*.env*`/`*.json` and treat hits as candidates, not confirmations. (secrets-audit)
- **`.env.local` shipped to staging** crosses the dev→staging secret boundary — a common real-world finding. (secrets-audit)
- **Anonymous maintainer >> single named maintainer** for takeover risk: if the GitHub identity is not tied to a real-world person, the risk is significantly greater. (supply-chain-risk-auditor)
- **Past CVEs on a hugely popular project may be a maturity signal, not a weakness** — more scrutiny yields more disclosed (and patched) CVEs. Weight CVE count *relative to* popularity/complexity. (supply-chain-risk-auditor)
- **Third-party credentials surfaced during the audit** (vendor keys, employee personal accounts) must be notified + rotated, not quietly fixed. (secrets-audit)

---

## Delegate to

- **dependency-audit** — use when you need the full framework-specific anti-pattern sweep, `npm audit fix` triage, monorepo manifest cataloging, or CI/CD + IaC supply-chain ingress review.
- **secrets-audit** — use when hunting leaked credentials across source/history/build artifacts, or auditing the secrets-management posture (storage hierarchy, rotation, scoped IAM, break-glass).
- **supply-chain-risk-auditor** — use when scoping dependency takeover/abandonment risk pre-engagement and producing a high-risk-dependency table with suggested alternatives (needs `gh`).
- **02-vulnerability-scanner** — use when you need OSV/NVD CVE enumeration with CVSS scoring, EPSS/KEV/SBOM/VEX prioritization, or config-hardening checklists (nginx/sshd/Docker/K8s) and network NSE scans.
- **container-audit** — delegate K8s `Secret` etcd-encryption and container runtime hardening details.
- **iam-audit** — delegate workload-identity-federation design (the long-lived-key alternative).
- **owasp-audit** — delegate in-source injection/access-control and finding disposition (Fixed/Deferred/Accepted-Risk).
