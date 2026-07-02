# redteam-master Routing Map

Decision guide: map an engagement to the right playbook + specialist skills. Authorized
testing only — every offense pairs with remediation. A finding does not exist until proven
with a concrete trigger/PoC or a traced source→sink flow. No fabricated tools/flags/CVEs.

**How to invoke:** call a skill by exact name via the **Skill tool** (e.g. Skill `owasp-audit`).
Playbooks (`references/playbooks/*.md`) carry inline-distilled techniques — read them for the
fast pass. **Delegate** to a named skill when you need full depth (orchestration, bundled
scripts, complete checklists). Inline = triage/recon/quick PoC; delegate = end-to-end audit.

---

## 1. Target type → playbook + specialists

| Target | Playbook | Primary skills | Support |
|---|---|---|---|
| Web app (server/SPA/hybrid) | `a-web-api` | owasp-audit, web-pentest, 09-web-security | insecure-defaults, security-payloads, security-webshells |
| REST / GraphQL / RPC API | `a-web-api` | api-audit, api-security-testing, owasp-audit | 09-web-security |
| Cloud account (AWS/GCP/Azure) | `b-cloud-container` | cloud-audit, iam-audit, 10-cloud-security | exploiting-cloud-platforms, secrets-audit |
| Container / K8s | `b-cloud-container` | container-audit, 10-cloud-security | exploiting-containers, dependency-audit |
| Mobile app (APK/IPA) | `g-mobile` | mobile-audit, 17-mobile-security, mobile-pentesting | firebase-apk-scanner, api-audit |
| Smart contract / chain | `f-blockchain` | solana-rust-deep-audit, web3-blockchain, per-chain scanners* | entry-point-analyzer, dimensional-analysis, token-integration-analyzer |
| AI / LLM app | `h-ai-llm` | 16-ai-llm-security, prompt-injection, agentic-actions-auditor | ai-risk-management, llm-testing |
| Native C/C++ binary (source) | `c-code-review-sast` | c-review, codeql, semgrep | variant-analysis, address-sanitizer |
| Native binary (no source) / firmware | `j-offensive-postex` | 04-reverse-engineering, 03-exploit-development | vuln-research |
| Source-code repo (managed langs) | `c-code-review-sast` | owasp-audit, codeql, semgrep | differential-review, sarif-parsing, variant-analysis |
| Network / host / perimeter | `i-recon-network` | recon, 01-recon-osint, initial-access-recon, 08-network-security | osint-recon, 02-vulnerability-scanner |
| Dependency tree / supply chain | `k-supply-chain-secrets` | dependency-audit, supply-chain-risk-auditor, 02-vulnerability-scanner | secrets-audit |
| Cryptography / TLS / protocol | `d-crypto` | crypto-audit, 13-crypto-analysis, constant-time-analysis | zeroize-audit, wycheproof, crypto-protocol-diagram |
| Parser / codec / untrusted-byte sink | `e-fuzzing` | security-fuzzing, harness-writing (+ engines: libfuzzer/aflpp/cargo-fuzz/atheris) | coverage-analysis, address-sanitizer |
| Post-engagement defense / IR / detections | `m-defense-detection` | siem-detection, threat-hunting, 07-incident-response, 15-blue-team-defense | 05-malware-analysis, yara-rule-authoring |

*Per-chain scanners: solana-vulnerability-scanner, cosmos-vulnerability-scanner,
cairo-vulnerability-scanner, substrate-vulnerability-scanner, ton-vulnerability-scanner,
algorand-vulnerability-scanner.

---

## 2. By intent — quick index

### Verify, triage, disposition
- Verify a suspected finding is real / not a false positive → **fp-check**
- Score & dispose one finding (mitigate / FP / accept-risk, CVSS) → **finding-triage**
- Adversarial re-audit to break correlated blind spots → **second-opinion** (or re-run owasp-audit adversarially)
- Read / dedupe / filter / convert scanner output → **sarif-parsing**

### Source review & SAST
- OWASP Top 10 code review → **owasp-audit**
- Diff / PR / commit review (regression detection, blast radius) → **differential-review**
- Sweep codebase for siblings of a confirmed bug → **variant-analysis**
- Run interprocedural taint (compiled/large code, custom wrappers) → **codeql**
- Fast multi-language scan / non-building code → **semgrep**
- Write a Semgrep rule for a pinned root cause → **semgrep-rule-creator** (variants: **semgrep-rule-variant-creator**)
- C/C++ memory-safety audit → **c-review**
- Project SARIF/weAudit onto a code graph → **audit-augmentation**

### Fuzzing & dynamic
- Fuzz a parser / codec / protocol → **security-fuzzing** + **harness-writing** (+ engine: libfuzzer/aflpp/cargo-fuzz/atheris/libafl)
- ASan/UBSan/MSan flags + crash decoding → **address-sanitizer**
- Measure harness reach / find magic-value blockers → **coverage-analysis**
- Break checksum/PRNG coverage walls → **fuzzing-obstacles**; build a dict → **fuzzing-dictionary**
- Measure test quality → **mutation-testing**; assert invariants → **property-based-testing**

### Crypto
- Algorithm/mode/KDF/IV/sig/key-lifecycle review → **crypto-audit**
- TLS/cipher posture + PQC migration → **13-crypto-analysis**
- Timing side-channel (static) → **constant-time-analysis**; (dynamic/statistical) → **constant-time-testing**
- Secret-wipe / DSE survival (IR/ASM evidence) → **zeroize-audit**
- Known-attack vector testing (malleability/DER/curve) → **wycheproof**
- Diagram a protocol before attacking → **crypto-protocol-diagram** (formalize → **mermaid-to-proverif**)

### Blockchain
- Map state-changing entry points + access levels → **entry-point-analyzer** (run first)
- Full Solana/Anchor/off-chain Rust audit → **solana-rust-deep-audit**
- EVM/DeFi exploitation methodology → **web3-blockchain**
- Annotate units/decimals on arithmetic → **dimensional-analysis**
- External-token integration risk → **token-integration-analyzer**
- Whitepaper vs implementation → **spec-to-code-compliance**

### Cloud / container
- Multi-cloud posture (IAM/net/storage/logging) → **cloud-audit**; identity depth → **iam-audit**
- Docker/Helm/K8s manifest + cluster posture → **container-audit**
- Offensive cloud / IMDS / privesc chains → **exploiting-cloud-platforms**; escapes → **exploiting-containers**

### AI / LLM
- OWASP LLM Top 10 assessment + harnesses → **16-ai-llm-security**
- Prompt-assembly / output-handling / confused-deputy code audit → **prompt-injection**
- GitHub Actions AI-agent workflow audit → **agentic-actions-auditor**
- AI governance (NIST AI RMF / EU AI Act / fairness) → **ai-risk-management**
- Ready jailbreak/bias/data-leak corpora → **llm-testing**

### Recon / network
- Structured target map (DNS/ports/fingerprint) → **recon**; at-scale automation → **01-recon-osint**
- People/org/leaked-data OSINT → **osint-recon**
- Offensive initial access (brute-force, buckets, JS secrets, IDS evasion) → **initial-access-recon**
- PCAP / IDS rules / firewall audit → **08-network-security**

### Offensive / post-ex
- Build a PoC/exploit → **03-exploit-development**; decide CVE reachability → **vuln-research**
- RE a binary/firmware/protocol → **04-reverse-engineering**
- Red-team C2 + OPSEC → **14-red-team-ops**; full engagement lifecycle/RoE → **red-team-engagement**
- AD attacks → **active-directory-attacks**; Linux privesc → **linux-privilege-escalation**; Windows privesc → **windows-privilege-escalation**
- Crack/spray hashes → **password-attacks**; Wi-Fi → **wireless-attacks**; phishing → **phishing-social-engineering**; egress/transfer → **file-transfer-techniques**

### Supply chain & secrets
- Dependency CVE audit + framework anti-patterns → **dependency-audit**
- Dependency takeover/abandonment risk → **supply-chain-risk-auditor**
- Leaked-credential + secrets-posture audit → **secrets-audit**
- OSV/NVD enumeration + EPSS/KEV/SBOM/VEX → **02-vulnerability-scanner**

### Defense / detection / IR / compliance
- Suspicious binary triage → **05-malware-analysis**; YARA authoring → **yara-rule-authoring**
- Hypothesis-driven hunt → **threat-hunting**; IOC/ATT&CK layers → **06-threat-hunting**
- Live incident → **incident-triage**; full PICERL → **07-incident-response**; disk → **disk-forensics**
- SIEM queries/Sigma → **12-log-analysis**; detection-as-code program → **siem-detection**; SOC → **soc-operations** / **11-csoc-automation**
- Hardening after red team → **15-blue-team-defense**; OT/ICS → **18-ot-ics-security**
- GRC crosswalk → **19-grc-compliance**; CSF → **csf-mapping**; PCI → **pci-audit**; HIPAA → **hipaa-audit**; privacy → **privacy-engineering**

---

## 3. Cross-cutting specialists (apply across all domains)

| Need | Skill | When |
|---|---|---|
| Kill false positives | **fp-check** | Any suspected bug before reporting; the verification gate |
| Disposition one finding | **finding-triage** | Scoring/mitigation/accept-risk on a single finding |
| Break blind spots | **second-opinion** | Adversarial re-pass, ideally a different agent/model |
| Audit scaffolding | **security-audit** | Orchestrate a multi-skill engagement end-to-end |
| Deep pre-finding context | **audit-context-building** | Line-by-line architectural read before hunting |
| Prep a repo for review | **audit-prep-assistant** | Set goals, run SAST, raise coverage, remove dead code (Trail of Bits checklist) |
| Maturity scorecard | **code-maturity-assessor** | Pre-audit posture read (9-category ToB framework) |
| Design-time risk | **threat-modeling** | Before code exists / new feature design |
| Learn from real breaches | **breach-patterns** | "Could X happen to us?" — apply known-attacker playbooks |
| Write up for stakeholders | **security-comms** | Translate findings to advisories / disclosure |
| Code graph / structure | **trailmark** (+ **trailmark-structural** / **trailmark-summary**) | Build call/blast-radius graph to scope reach |
| GitHub operations | **gh-cli** | PRs/issues/advisory data; exact star/issue counts |
| Persist engagement knowledge | **codebase-memory** | Knowledge graph across sessions on one codebase |

---

## 4. Routing logic (resolve fast)

1. **Live target vs source?** Source → SAST/audit cluster (`c`, domain-specific). Live host
   with authorization → recon (`i`) first, then hand off by asset type.
2. **Confirm authorization & scope before any active touch** (every offensive playbook gates on
   this — `i`, `j`, `g`, `h`, `a` live mode). No written scope → stop and ask.
3. **Pick the most specific domain playbook**, not the generic one. Smart contract → `f` (not
   generic source review). LLM web endpoint → `h` for the AI slice + `a` for the HTTP shell.
4. **Chain across clusters** — most engagements span several:
   - SSRF (`a`) → IMDS → cloud creds (`b`).
   - Recon (`i`) → web app (`a`) / cloud (`b`) / services (`k` CVEs).
   - Source bug found (`c`) → variant sweep (`variant-analysis`) → PoC (`j`) → fuzz harness (`e`).
   - Crypto in HTTP path (`a` JWT/webhook) → deep crypto (`d`).
   - Any offensive engagement → defensive write-up + detections (`m`).
5. **Always close the loop:** verify with **fp-check**, dispose with **finding-triage**, and pair
   every finding with a remediation. Offensive output (`j`) feeds defensive detections (`m`).
