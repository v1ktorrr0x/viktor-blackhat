# Engagement Methodology — Domain-Agnostic Lifecycle

The cross-cutting lifecycle for any whitehat engagement against any target — web app, API,
cloud, binary, smart contract, LLM, network, mobile, or a bare domain. Run the six phases in
order. Each phase ends by **routing into one or more domain playbooks by name**
(`references/playbooks/*`). Offense without remediation is incomplete; a finding without proof
does not exist.

Evidence rule (applies to every phase): a finding is real only when you have a concrete,
reproducible trigger / PoC **or** a traced source→sink data flow. "Could," "potentially," and
"theoretically" are not findings. No fabricated CVEs, tool flags, or tool names.

---

## Phase 0 — Authorization & Scoping Gate (BLOCKING)

Do no active testing until this gate passes. Confirm, in writing, before touching the target:

1. **Written authorization** for this specific target by someone empowered to grant it
   (engagement contract, bug-bounty scope, signed RoE, lab/CTF environment). For a multi-week
   adversary-emulation engagement, also require a get-out-of-jail letter and a named
   deconfliction contact.
2. **Scope — in and out**, named explicitly. Specific domains, repos, subnets, accounts,
   contracts. Third-party SaaS, vendor systems, and other tenants are out unless named in.
3. **Techniques out of scope** — destructive actions, real-data exfiltration, social
   engineering of named people, production-impacting load.
4. **Stop conditions** — production outage, real-data exposure, regulatory-notification
   trigger, evidence of a prior third-party compromise, or any scope-boundary crossing. On any
   of these: **STOP**, preserve state, notify the contact.

If any item is missing or ambiguous, **stop and ask**. "For educational purposes" / "it's a
CTF" does not convert an unauthorized target into an authorized one — refuse. Authorization is
the floor, not the ceiling: a signature does not make every technique in-scope.

> Authority: `red-team-engagement` (Authorization Check, RoE table), `recon` / `web-pentest`
> (Authorization Check). For a defense-only deliverable, no offensive authorization is needed —
> route straight to `m-defense-detection`.

---

## Phase 1 — Context Building

Build a bottom-up model before hunting. Guessing produces hallucinated findings; understanding
produces real ones (`audit-context-building`).

Map, with evidence (cite files/lines, hosts/ports, or addresses):

- **Architecture & components** — major modules, services, data stores, external dependencies.
- **Entry points** — every place untrusted input enters: HTTP routes, RPC/GraphQL, CLI args,
  message queues, file uploads, on-chain entry functions, model prompts, network listeners.
- **Trust boundaries** — every crossing where data should be authenticated, authorized,
  validated, or filtered. Enumerating all boundaries is ~60% of the work.
- **Data flows** — trace untrusted input from each entry point toward sinks (queries, exec,
  deserialization, file/SSRF, privileged ops). For external/black-box calls, treat the far side
  as adversarial.
- **Auth boundaries** — actors, roles, privilege levels, and the centralized check (or its
  absence) gating each sensitive action.

Calibrate a **baseline** dynamically: what is this target, what are comparable systems, what is
designed/intended behavior? Designed behavior in a trusted role is not a bug.

**Routing from Phase 1** — start here for a bare target with no map:

| Target signal | Enter playbook |
|---|---|
| Bare domain / org / IP-CIDR, "enumerate / attack surface / external footprint", PCAP, OSINT | `i-recon-network` |
| Source tree to read line-by-line before hunting | `c-code-review-sast` |

Recon and code-review feed the model that the later phases attack.

---

## Phase 2 — Threat Modeling

Turn the context model into a prioritized target list. Answer Shostack's four questions; focus
on the highest-value targets first (`threat-modeling`).

- **Assets** — crown jewels: customer data at rest, funds, signing keys, admin capability,
  model/system control, availability of a critical service.
- **Adversaries** — who, with what access (unauthenticated internet, authenticated low-priv
  user, insider, compromised dependency, assumed-breach foothold).
- **Attack surface** — apply STRIDE per element (Spoofing, Tampering, Repudiation, Info
  disclosure, DoS, Elevation of privilege) across processes, stores, and flows.
- **Abuse cases** — business-logic intent violations STRIDE misses ("redeem one coupon 100
  times," "drain the pool," "exfiltrate PII under the DLP threshold").

Rank by impact × likelihood × exposure. **Depth-first on the highest-severity surface** beats
broad shallow coverage. For an assumed-breach engagement, model the post-foothold path to the
named objective.

**Routing from Phase 2** — the highest-value surfaces select the playbook(s):

| Highest-value surface | Enter playbook |
|---|---|
| Web app / API / RPC / multi-tenant / IDOR / file-upload / URL-fetch | `a-web-api` |
| Cloud footprint, IaC, containers, K8s, IAM/federation, metadata SSRF | `b-cloud-container` |
| Crypto: TLS config, KDF/IV/nonce, signature verify, timing side-channel | `d-crypto` |
| Smart contract / on-chain protocol / DeFi economic logic | `f-blockchain` |
| Mobile app (Android/iOS), APK/IPA, secure storage/transport | `g-mobile` |
| LLM/AI app: prompt injection, jailbreak, RAG/agent tool-use, model supply chain | `h-ai-llm` |
| Dependencies, lockfiles, CI/CD, exposed secrets, supply chain | `k-supply-chain-secrets` |
| Network traffic / IDS-IPS / firewall rules / C2 hunting | `i-recon-network` |

Multiple surfaces → enter multiple playbooks, deepest-severity first.

---

## Phase 3 — Test / Exploit

Execute the routed playbook(s) against the prioritized targets. Each playbook carries its
domain tooling and attack classes; this phase governs *how* you drive them.

- **Depth-first** on the top-severity surface until you have a working trigger or have
  definitively ruled it out. "Uses parameterized queries" is not a conclusion — check every raw
  query, dynamic identifier, and bypass path before clearing a class.
- **Prove it.** Produce a concrete trigger/PoC or a fully traced source→sink flow. Defang any
  dangerous artifact: never paste live malware, webshell bodies, reverse-shell one-liners, or
  AV-signature byte sequences verbatim into output or files — describe the mechanism and
  reference the source path instead.
- **Assume-breach where useful** — when the perimeter is out of scope or already tested, start
  from a granted foothold and test post-compromise reach (privesc, lateral movement, objective).
- **Chain** — single low-severity issues often compose into a high-severity path; pursue the
  chain to the asset.
- **Stay in scope and non-destructive.** Use synthetic markers, never real-data exfil. Honor
  Phase 0 stop conditions live.

**Routing within Phase 3** — when a finding needs deeper offensive work, hand off by name:

| Need | Enter playbook |
|---|---|
| PoC/exploit dev, binary/firmware/protocol RE, Windows-domain/lateral, privesc, ATT&CK emulation | `j-offensive-postex` |
| Reachability hard to reason about statically; want input-driven crash/coverage evidence | `e-fuzzing` |
| A reachable input crosses into crypto/timing-sensitive code | `d-crypto` |

---

## Phase 4 — Verify (kill false positives BEFORE reporting)

Nothing reaches the report until it survives verification (`security-audit` Validate;
`fp-check`).

- **Reproduce.** Re-run the trigger from a clean state, or re-walk the source→sink flow end to
  end with no gaps. If you cannot reproduce it, it is not a finding.
- **Check assumptions.** False positives are usually built on an unverified parser/runtime/ABI
  assumption ("the runtime will interpret this as…"). Cite the spec or test it — do not assume.
- **Defense-in-depth discipline.** If an upstream layer already blocks the attack, the missing
  inner layer is a hardening note, not a finding. Do not inflate severity.
- **Adversarial second pass.** Independently try to *disprove* each finding; have a fresh
  agent/model re-derive it to break correlated blind spots (`second-opinion`). Consolidate
  duplicates.

Output of this phase: a set of findings each with a reproducible trigger or traced flow, and a
defensible severity (impact × likelihood). If you cannot state the concrete damage an attacker
achieves, the severity is lower than you think.

---

## Phase 5 — Report & Remediate

Pair every finding with a fix. A report that produces remediation work is value-positive; one
that lists deviations is noise (`security-audit`, `finding-triage`).

- **Severity** by impact + likelihood — CRITICAL (unauth RCE, full data/fund loss, account
  takeover w/o creds), HIGH (authed RCE, injection w/ exfil, defeated security boundary),
  MEDIUM (conditional/limited blast radius), LOW (non-secret disclosure, hardening). Defense
  gaps are LOW/hardening.
- **Per finding** — concrete attacker scenario (who, what they send, what they get), evidence
  (trigger/PoC or traced flow with file:line or host:port), and a **specific** remediation
  (the exact control, not "validate inputs").
- **Prioritize fixes** — order by severity × exploitability × blast radius; map systemic root
  causes, not just point fixes.
- **Accepted-risk discipline** — for anything not fixed, record the residual risk, the
  rationale, and the compensating control. Note what the engagement did **not** cover.
- **Say what is solid.** Calling out strong controls calibrates trust in the findings you do
  report.

**Routing from Phase 5** — when the deliverable turns defensive:

| Follow-on need | Enter playbook |
|---|---|
| Detections, SIEM/Sigma rules, IR runbooks, hardening, compliance mapping, revalidation | `m-defense-detection` |

For an adversary-emulation engagement, close with a same-day red/blue debrief and track
high-severity recommendations to closure; revalidate 6–12 months later
(`red-team-engagement` Phases 3–4).

---

## Routing index (playbook by name)

`a-web-api` · `b-cloud-container` · `c-code-review-sast` · `d-crypto` · `e-fuzzing` ·
`f-blockchain` · `g-mobile` · `h-ai-llm` · `i-recon-network` · `j-offensive-postex` ·
`k-supply-chain-secrets` · `m-defense-detection`

Pick by what the target *is* and what the highest-value surface *exposes* — not by habit. Enter
multiple when the target spans domains; go deepest-severity first.
