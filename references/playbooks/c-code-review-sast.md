# Source Code Review & Static Analysis (SAST) Playbook

Whitehat-only. This playbook governs deep source-level audits: C/C++ memory-safety review,
CodeQL/Semgrep taint tracking and rule authoring, SARIF triage, security code patterns,
differential (PR/diff) review, variant analysis, blast-radius, and code-maturity scoring.
Findings here feed remediation — every finding gets a root cause, an attack path, and a fix.

---

## When this applies

Route an engagement here when you see any of:

- **Native C/C++ targets:** daemons, services, parsers, network listeners, codecs, IPC, SUID
  binaries, Windows userspace services. Signals: `*.c/*.cpp/*.cc/*.cxx/*.h/*.hpp`, includes of
  `<pthread.h>`, `<sys/socket.h>`, `<unistd.h>`, `<windows.h>`, `<winsock.h>` (c-review).
- **You have source** (not just a binary) and want interprocedural data-flow, not just grep.
- **A PR / commit / diff** to review for introduced regressions or removed checks (differential-review).
- **One bug already found** and you need to sweep the codebase for siblings (variant-analysis).
- **Scanner output to triage** — SARIF from CodeQL/Semgrep that needs dedup, filtering, prioritization (sarif-parsing, audit-augmentation).
- **A pre-audit maturity read** is requested (code-maturity-assessor).

Do NOT route here for: kernel/driver code, pure binary-only RE (use reverse-engineering), or
runtime/DAST testing. c-review explicitly excludes kernel modules, managed languages, and
bare-metal-without-libc.

---

## Methodology

### Phase 0 — Scope & threat model (do this first, never skip)
1. Fix two distinct scopes and keep them separate the whole engagement (c-review):
   - `finding_scope_root` — the subtree you may *file findings* in.
   - `context_roots` — read-only roots you may *inspect* to prove reachability/callers/mitigations
     (default `.`). Reading context outside scope is allowed; filing findings there is not.
2. Resolve the **threat model** explicitly — it changes which inputs are "tainted":
   `REMOTE` (network/attacker), `LOCAL_UNPRIVILEGED` (local users untrusted), or `BOTH` (c-review).
   For CodeQL this maps to `--threat-model` groups: `remote` (default), `local`, `environment`,
   `database`, `file`, `all` (codeql/threat-models).
3. Map **entry points** (where untrusted data enters: network, files, CLI, IPC, env) and
   **trust boundaries** (sandboxed vs. trusted peer vs. arbitrary remote). Note existing hardening:
   fuzzers, sanitizers, privilege separation (c-review Phase 3 context.md).

### Phase 1 — Recon & map the attack surface
4. Detect language/platform: `is_cpp`, `is_posix`, `is_windows` from extensions + include greps (c-review).
5. Probe for build metadata: `compile_commands.json` (CMake `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`,
   Bear, or compiledb). Its presence enables richer extraction; absence lowers reachability confidence.
6. Enumerate the sinks the language model already recognizes before writing custom rules — run the
   CodeQL diagnostic queries (`RemoteFlowSource` source enumeration, per-language sink enumeration)
   to see what's modeled and, critically, what is *not* (the unmodeled custom wrappers are where bugs hide).

### Phase 2 — Run the scanners (broad net)
7. **Pick the engine to fit the job** (variant-analysis tool table):
   - ripgrep → fast recon / hotspot finding, zero setup.
   - Semgrep → easy syntax, no build, works on non-building/incomplete code.
   - Semgrep taint / CodeQL taint → follows values across functions.
   - CodeQL → best interprocedural / cross-function precision (needs a buildable DB for compiled langs).
8. Run **all** relevant rule sources, including third-party (these are required, not optional):
   official suites + Trail of Bits + 0xdea (C/C++) + Community Packs. "security-extended is the
   baseline, not the ceiling" (codeql); "Trail of Bits / 0xdea / Decurity catch what the registry
   misses" (semgrep).
9. Preserve raw output; produce SARIF; never report "clean" off a single suite.

### Phase 3 — Triage & verify (the real work)
10. Parse SARIF: count, group by rule, filter by level, dedupe by fingerprint (sarif-parsing).
11. For each candidate, decide TRUE/FALSE positive by hand — trace source→sink, check sanitizers,
    confirm reachability from a real entry point. Zero findings demands investigation, not celebration
    (poor DB quality, missing models, wrong packs, silent suite filtering can all yield false zeros).
12. **Rate exploitability** with a concrete attacker model: WHO / WHAT access / WHERE they interact,
    then EASY / MEDIUM / HARD (differential-review/adversarial).

### Phase 4 — Variant sweep & blast radius
13. For every confirmed bug, run variant analysis across the **entire** codebase (not just the
    module it was found in) — climb the abstraction ladder one change at a time (variant-analysis).
14. Compute blast radius quantitatively (count transitive callers) for HIGH-risk changes; missing
    tests on a changed path elevates severity (differential-review).

### Phase 5 — Report
15. Each finding: root cause at `file:line`, attack path, exploitability rating, concrete (measurable)
    impact, PoC, blast radius, and the fix. Emit a stable SARIF artifact even on zero findings so
    downstream consumers get a consistent set.

---

## High-signal checklist (CROWN JEWELS — preserve verbatim)

### C/C++ memory-safety bug classes (c-review clusters; CWEs added)
- **Unbounded buffer write sinks** — `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets` (CWE-120/787).
  Their bounded forms `strncpy`/`strncat`/`snprintf`/`strlcpy`/`strlcat` act as sanitizers but
  have their own truncation/NUL pitfalls (see gotchas).
- **Format string** — any `printf`/`fprintf`/`sprintf`/`snprintf`/`syslog` where the format
  argument is a *variable*, not a literal (CWE-134). Semgrep core pattern: match `printf($VAR)` etc.
  and `pattern-not: printf("...")` to exclude literal formats.
- **Integer overflow → undersized allocation** — `$SIZE = $X * $Y; ... malloc($SIZE)`, `malloc($X*$Y)`,
  `calloc($X*$Y, ...)` (CWE-190 → CWE-122/787). Attacker-controlled size reaching `malloc`/`calloc`/
  `realloc`/`alloca` without an overflow check is the canonical heap-overflow primitive.
- **Use-after-free / double-free / type confusion** — dominant C++ classes (c-review scope).
- **Race conditions / TOCTOU** — POSIX threads/signals; check/use gaps on files (`access()` then `open()`).
- **Command injection** — tainted data into `system`, `popen`, `execl`, `execlp`, `execle`, `execv`,
  `execvp`, `execvpe` (arg 0 / command string) (CWE-78).
- **Path traversal** — tainted path into `fopen`, `open`, `freopen`, `access`, `stat`, `lstat`
  without canonicalization (CWE-22).

### Untrusted-input SOURCES to taint (C/C++, from variant-analysis cpp.ql)
`argv` parameter; `gets`, `fgets`, `scanf`, `fscanf`, `sscanf`, `getline`, `getchar`, `fgetc`;
`recv`, `recvfrom`, `recvmsg`, `read` (network); `getenv` (environment); `fread`, `fgets` (file).

### Differential-review red flags (stop and investigate — differential-review)
- Removed code from a commit whose message contains `security`, `fix`, `CVE`, `vulnerability`
  (security regression). Detect: `git log -S "pattern" --all --grep="security\|fix\|CVE"`.
- Access-control modifiers removed/relaxed (e.g. `onlyOwner` removed, `internal`→`external`).
- Validation removed without replacement: `git diff <range> | grep "^-.*require"` (and `assert`, `revert`).
- New external calls added without checks: `git diff <range> | grep "^+" | grep -E "\.call|\.delegatecall|\.staticcall"`.
- High blast radius (50+ callers) + HIGH-risk change.
- **Heartbleed was 2 lines** — classify by RISK, not diff size.

### Differential-review quick grep arsenal
```bash
# Removed security checks
git diff <range> | grep "^-" | grep -E "require|assert|revert"
# Changed access modifiers
git diff <range> | grep -E "onlyOwner|onlyAdmin|internal|private|public|external"
```

### Variant analysis — the abstraction ladder (variant-analysis METHODOLOGY)
Write the root cause as one sentence — *that sentence is your search pattern*:
> "This vuln exists because [UNTRUSTED DATA] reaches [DANGEROUS OPERATION] without [REQUIRED PROTECTION]."

| Level | What you abstract | Example | FP rate |
|-------|-------------------|---------|---------|
| 0 | nothing (exact match) | `rg 'SELECT \* FROM users WHERE id=" \+ request\.args\.get'` | 0% — baseline, confirms bug |
| 1 | variable names → metavars | `$QUERY = "SELECT * FROM users WHERE id=" + $INPUT` | low — copy-paste variants |
| 2 | structure | concat used inside `cursor.execute($Q)` | medium |
| 3 | semantics (taint) | any `request.args.get`/`request.form.get` → any `cursor.execute` | high — needs triage |

Rules: **one change at a time**, re-run, review *all* new matches, keep or revert.
**Stop when FP rate > ~50%.** Acceptable FP by context: CI-blocking <5%, dev warning <20%,
audit triage <50%, research <80%.

### Variant analysis — expand the bug class (don't tunnel on one term)
- Same-semantic siblings: bug on `isAuthenticated` → also check `isActive`, `isAdmin`, `isVerified`, `isLoggedIn`;
  `userId` → `ownerId`, `creatorId`, `authorId`.
- **Null-equality bypass:** `order.owner_id == current_user.id` is `True` when both are `None`
  (anonymous user vs. guest-owned object) — a real authorization bypass.
- **Doc/code mismatch:** function named `deny`/`restrict`/`block`/`forbid` whose return-value
  semantics are inverted. Search those names, manually verify the return logic.
- Edge cases that reveal hidden bugs: null/None/undefined, empty string vs null, zero vs null, empty collection.

### Semgrep rule authoring — taint mode (semgrep-rule-creator)
- **Prioritize taint over pattern matching** for injection: `eval($X)` matches both the vulnerable
  `eval(user_input)` and safe `eval("literal")`; taint only fires when data actually flows.
- Required taint skeleton:
```yaml
mode: taint
pattern-sources:   [- pattern: request.args.get(...)]
pattern-sinks:     [- pattern: eval(...)]
pattern-sanitizers:[- pattern: sanitize(...)]   # optional
```
- **Metavariables MUST be uppercase** (`$X`, `$FUNC`), `$_` = anon, `$...VAR` = ellipsis metavar,
  `<... pattern ...>` = deep expression operator.
- **Typed metavariables** cut FPs: C/C++ `(int $X)`, `(int16_t $X)`; Java `(java.util.logging.Logger $LOGGER)`;
  Go `($READER : *zip.Reader)`; TS `($X: DomSanitizer)`.
- Filters: `metavariable-regex`, `metavariable-pattern`, `metavariable-comparison` (`$NUM > 1024`),
  `focus-metavariable`, `by-side-effect: only`.
- **Test-first is mandatory.** Only `ruleid:` / `ok:` annotations allowed (no multi-line `/* ruleid */`,
  no `todook`/`todoruleid`). 100% pass required. One rule per YAML, never `languages: generic`.
- Debug: `semgrep --dump-ast --lang <lang> file`, `semgrep --dataflow-traces --config rule.yaml file`,
  `semgrep --test --config <rule-id>.yaml <rule-id>.<ext>`, `semgrep --validate --config rule.yaml`.

### Semgrep scan hygiene (semgrep)
- **Every** `semgrep` invocation carries `--metrics=off` (default + `--config auto` phone home).
- Check Pro first: `semgrep --pro --validate --config p/default` — Pro adds cross-file taint and
  catches ~250% more true positives; OSS cannot track flow across files.
- Important-only = pre-filter `--severity MEDIUM --severity HIGH --severity CRITICAL` then post-filter
  metadata `category=security AND confidence∈{MEDIUM,HIGH} AND impact∈{MEDIUM,HIGH}`. Third-party
  rules lacking that metadata are **kept** (can't filter what isn't annotated).

### CodeQL run discipline (codeql)
- **Never pass pack names directly** to `codeql database analyze` — each pack's `defaultSuiteFile`
  silently applies filters and can return zero results. Always generate an explicit `.qls` suite.
- A database that *builds* is not automatically *good*: run `codeql database print-baseline`, check
  `baselineLinesOfCode > 0`, extractor errors < 5% of project files, `finalised: true`.
- macOS Apple-Silicon **exit code 137 = arm64e/arm64 mismatch**, NOT a build failure — try Homebrew
  arm64 toolchain or Rosetta before falling back to `build-mode=none` (last resort; produces incomplete analysis).
- Data extensions catch what CodeQL misses — even Django/Spring/Express apps have custom wrappers
  around DB/request/shell calls. Skipping extensions = missing project-specific paths.

### SARIF triage one-liners (sarif-parsing)
```bash
jq '[.runs[].results[]] | length' results.sarif                                   # total findings
jq '[.runs[].results[].ruleId] | unique' results.sarif                            # rules triggered
jq '.runs[].results[] | select(.level == "error")' results.sarif                  # errors only
jq '[.runs[].results[]] | group_by(.ruleId) | map({rule:.[0].ruleId,count:length}) | sort_by(-.count)' results.sarif
# CSV export for a tracking sheet
jq -r '.runs[].results[] | [.ruleId,.level,.locations[0].physicalLocation.artifactLocation.uri,.locations[0].physicalLocation.region.startLine,.message.text] | @csv' results.sarif
```
- **Fingerprint, don't path-match:** tools report `/path/to/project/` vs `/github/workspace/`, so
  path matching fails across runs. Prefer `partialFingerprints`/`fingerprints`; fall back to
  `(ruleId, uri, startLine)`. Hash the *code snippet* for environment-independent stability.
- Always use defensive access (`result.get("locations",[{}])[0]...`) — most SARIF fields are optional.
- Stream 100MB+ files with `ijson` instead of loading whole.

---

## Tools & commands (only flags named in the source skills)

### CodeQL
```bash
codeql --version
codeql database create $DB --language=$LANG --source-root=./src --overwrite
codeql database print-baseline -- "$DB"
codeql database export-diagnostics --format=text -- "$DB"
codeql resolve database --format=json -- "$DB"
codeql resolve qlpacks                 # verify installed packs
codeql resolve queries "$SUITE_FILE"   # verify the suite resolves BEFORE analyzing
codeql pack download trailofbits/cpp-queries
codeql pack download GitHubSecurityLab/CodeQL-Community-Packs-CPP
codeql database analyze $DB \
  --format=sarif-latest --output="$RAW_DIR/results.sarif" --threads=0 \
  --threat-model local --threat-model environment \
  --model-packs=myorg/java-models --additional-packs=./lib/codeql-models \
  -- "$SUITE_FILE"
# extractor knobs for poor extraction
export CODEQL_EXTRACTOR_CPP_OPTION_TRAP_HEADERS=true
export CODEQL_EXTRACTOR_JAVA_OPTION_JDK_VERSION=17
```
Suites: `codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls`.
Run-all coverage = import BOTH `security-and-quality` (excludes `experimental/`) AND
`security-experimental` (includes experimental, excludes quality). Threat-model flag is **singular**
`--threat-model` (repeatable; `!name` disables, e.g. `--threat-model all --threat-model '!database'`).

### Semgrep
```bash
semgrep --pro --validate --config p/default        # Pro availability check
semgrep --metrics=off --config p/security-audit --config p/secrets <abs-target>
semgrep --pro --metrics=off --severity MEDIUM --severity HIGH --severity CRITICAL \
  --config <ruleset> --json -o out.json --sarif-output=out.sarif <abs-target>
semgrep --test --config <rule-id>.yaml <rule-id>.<ext>
semgrep --validate --config <rule-id>.yaml
semgrep --dump-ast --lang <lang> <file>
semgrep --dataflow-traces --config <rule-id>.yaml <file>
```
Always-include baseline: `p/security-audit`, `p/secrets`. Third-party (required by language):
Trail of Bits (Py/Go/Ruby/JS/TS/Terraform), **0xdea (C/C++ memory safety)**, Decurity (Solidity/Cairo/Rust),
dgryski (Go), MindedSecurity (Android), Apiiro (malicious-code/supply-chain).

### Variant analysis / recon
```bash
rg -n "exact_vulnerable_code_here"                 # Level 0 baseline
rg "pattern" --glob '!**/test*' --glob '!**/*_test.*'   # exclude tests
```
CodeQL C/C++ taint template: `import semmle.code.cpp.dataflow.new.TaintTracking`,
`module Cfg implements DataFlow::ConfigSig { isSource / isSink / isBarrier }`,
`TaintTracking::Global<Cfg>`.

### SARIF
`jq` (CLI), `pysarif`, `sarif-tools` (`sarif summary|ls|diff|csv|html`), `ijson` (streaming),
`ajv validate -s sarif-schema-2.1.0.json -d results.sarif`. Augment a code graph:
`uv run trailmark augment <dir> --sarif results.sarif --weaudit .vscode/<user>.weaudit --json`
(audit-augmentation; run `engine.preanalysis()` first so findings cross-reference blast radius/taint).

---

## Expert gotchas / bypasses

- **Bounded string funcs are not free wins.** `strncpy` does not NUL-terminate on truncation;
  `snprintf` can truncate silently. variant-analysis lists them as sanitizers/barriers, but a
  truncated path/host can still be a logic bug — verify, don't assume safe.
- **Zero findings ≠ secure.** It often means a broken DB (cached/empty build, wrong `--source-root`,
  `baselineLinesOfCode == 0`), missing models for custom wrappers, wrong pack, or a `defaultSuiteFile`
  silently filtering everything. Investigate before reporting clean (codeql).
- **Cached compiled-language build = "No source code seen" in the build log = empty DB.** Force
  `make clean` then rebuild (codeql).
- **Compiled-language `src.zip` is inflated 10-20x by system headers.** Compare against
  project-relative files only; use `baselineLinesOfCode` as the primary quality metric (codeql).
- **Don't background the parallel workers.** In c-review's orchestrator, "parallel" = one message
  with M Agent calls; `run_in_background=true` defeats the primer cache and silently makes every
  worker pay full cache-creation. The cost failure is silent; the sequential failure is loud.
- **Refactors are HIGH until proven LOW.** "Just a refactor" breaks invariants; analyze as HIGH (differential-review).
- **Pattern too specific misses the variant; too generic drowns you in FPs.** The discipline is the
  ladder + one-change-at-a-time, measuring FP rate at each rung (variant-analysis).
- **Semgrep `--config auto` and default telemetry leak code during an audit** — `--metrics=off` always.
- **OSS Semgrep cannot cross files.** If the bug is an inter-file source→sink flow and you have no
  Pro license, switch to CodeQL rather than declaring no-flow (semgrep / variant-analysis).
- **Important-only filters can hide real bugs:** third-party rules lacking `confidence`/`impact`
  metadata are deliberately kept; do not "tidy" them out. Medium-precision queries with
  `security-severity >= 6.0` (e.g. `cpp/path-injection` 7.5) are kept on purpose (codeql important-only).
- **Concrete impact only.** "Could cause issues" is not a finding. State the exact funds drained,
  privilege escalated, or data exposed, with a reproducing PoC (differential-review/adversarial).
- **Search the whole repo.** The #1 variant-analysis miss is searching only the module where the
  original bug lived (e.g. fixed in `api/handlers/`, identical bug ships in `utils/auth.py`).

---

## Delegate to

- **c-review** — full orchestrated C/C++ memory-safety audit (47–64 bug-class clusters, dedup +
  FP/severity judges, SARIF output). Use when the target is native C/C++ and you want depth/coverage
  beyond a manual pass.
- **codeql** — build a CodeQL DB and run interprocedural taint/data-flow. Use for compiled or
  large codebases where you have a build and need cross-function precision and custom data extensions.
- **semgrep** — fast multi-language scan with parallel workers, Pro cross-file taint, third-party
  rulesets. Use for first-pass breadth, non-building code, or quick coverage.
- **semgrep-rule-creator** — author a tested taint/pattern rule for a specific bug. Use when you've
  pinned a root cause and want a precise, reusable detector.
- **variant-analysis** — sweep for siblings of a confirmed bug. Use immediately after any first find.
- **sarif-parsing** — read/dedupe/filter/convert SARIF from any tool. Use to triage and merge scanner output.
- **audit-augmentation** — project SARIF/weAudit findings onto a Trailmark code graph and
  cross-reference with blast-radius/taint. Use to prioritize a large finding set by structural reach.
- **differential-review** — security review of a PR/commit/diff with git-history regression detection
  and blast radius. Use for change-based reviews and adversarial modeling of HIGH-risk changes.
- **security-patterns** — SecLists regexes (API keys, SSNs, credit cards, IPs, emails) for secret/PII
  discovery in code and logs. Use as a grep companion during recon.
- **code-maturity-assessor** — Trail of Bits 9-category maturity scorecard (arithmetic, access
  control, complexity, testing, low-level code, etc.). Use for pre-audit posture reads and reporting.

---

## Cross-references (overlapping domain clusters)

- **Fuzzing & dynamic analysis** — sanitizers (ASan) confirm the memory bugs SAST flags; harness
  the entry points mapped in Phase 1.
- **Web/API & injection audits** — owasp-audit / api-audit share the source→sink taint model
  (SQLi, XSS, SSRF, command injection) for managed languages.
- **Smart-contract / DeFi review** — differential-review and variant-analysis patterns (reentrancy,
  access-control bypass, double-decrement, integer overflow) originate from on-chain audits.
- **Secrets & supply-chain** — security-patterns regexes and Semgrep `p/secrets` /
  Apiiro malicious-code rules overlap with dependency/secrets auditing.
- **Triage & reporting** — finding-triage / fp-check consume the TRUE/FALSE-positive verdicts and
  SARIF produced here.
