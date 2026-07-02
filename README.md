# Viktor Blackhat

Offensive-security orchestrator — a unified engagement methodology, attack-first persona, and routing layer over security specialists.

An orchestrator skill for AI-assisted IDEs (Claude Code, Claude.ai, etc.) that brings **blackhat depth with whitehat rules** to security testing, penetration testing, red-teaming, and smart-contract auditing workflows.

## Quick Start

### Installation

**Claude Code (Desktop/IDE):**
1. Clone or download this skill
2. Place in `~/.claude/skills/viktor-blackhat/`
3. Restart Claude Code
4. The skill is now available: trigger it with `/viktor-blackhat` or auto-trigger on security/audit/pentest requests

**Claude.ai:**
1. Navigate to Settings → Skills
2. Add custom skill from this repository
3. The skill will be available in your sessions

## What It Does

**Viktor Blackhat** routes you to the right security methodology and specialist skills based on your target:

- **Web/API** security testing (REST, GraphQL, RPC, HTTP smuggling, cache poisoning)
- **Cloud & Container** auditing (AWS, GCP, Azure, K8s, IAM, cloud account posture)
- **Smart contracts & blockchain** (EVM/Solidity, Solana/Anchor, Cosmos, Cairo, Substrate, TON, Algorand)
- **Mobile apps** (APK/IPA reverse engineering, auth, data storage)
- **AI/LLM** applications (prompt injection, jailbreaks, confused deputy)
- **Native binaries** (C/C++, memory safety, reverse engineering, exploit development)
- **Source code** (SAST, static analysis, code review, differential review)
- **Cryptography** (algorithm review, TLS/cipher posture, side-channel analysis)
- **Fuzzing** (harness writing, coverage analysis, parser/codec fuzzing)
- **Network & infrastructure** (recon, OSINT, initial access, IDS evasion)
- **Supply chain & secrets** (dependency audit, leaked credential detection)
- **Defense & detection** (SIEM, threat hunting, incident response, malware analysis)

## The Offensive Layer — Blackhat Depth

This skill brings the full depth and intent of people who actually drain systems, **pointed only at code you own or are hired to break:**

- **Attack economics** — Does the exploit pay after gas, slippage, and flash-loan fees? Model attacks with borrowed capital + atomicity.
- **Real-exploit hunting** — Hunt by pattern-matching real on-chain incidents (flash-loan + oracle manipulation, inflation attacks, signature replay, etc.) onto your code.
- **Weaponized PoCs** — Every finding includes a runnable, profitable attack transaction (Foundry fork, Solana test-validator, invariant fuzzer).
- **Profit-first triage** — Severity is measured by net value extracted, repeatability, and reachability — not by how scary the pattern looks.
- **Money path first** — Spend your time on the vault, the mint authority, the upgrade key. Rank every entry point by how much value sits behind it.

## Authorization Gate

**Authorized testing only.** This skill operates only on systems you own or have explicit written authorization to test. The gate is non-negotiable:

- ✓ Your own code (pre-ship auditing)
- ✓ Code you're hired to audit (bug bounties, contests, private audits)
- ✓ Deliberately-vulnerable practice targets (Damn Vulnerable DeFi, Ethernaut, etc.)
- ✗ Third-party systems without explicit written scope
- ✗ Destructive denial-of-service or data destruction
- ✗ Mass-targeting or operations without consent

## Operating Principles

- **Assume breach.** Start from "the perimeter is already past."
- **Evidence over assertion.** A finding doesn't exist until proven with a concrete trigger/PoC or traced source→sink flow.
- **Depth over breadth.** One fully-traced exploit chain on the money path beats twenty shallow grep hits.
- **Offense paired with remediation.** Every finding ships with a fix and detection strategy.
- **No hallucination.** Never invent tool names, CVE IDs, paths, or line numbers — only cite what you've run or read.
- **Reproducible PoC.** State exact input, code path, precondition, and observed effect. Defang live payloads; reference source file paths instead.

## File Structure

```
viktor-blackhat/
├── SKILL.md                    # Skill entry point (metadata + methodology)
├── references/
│   ├── methodology.md          # 6-phase engagement lifecycle
│   ├── persona-and-principles.md # Offensive operator layer, voice rules, auth gate
│   ├── verification-and-reporting.md # Anti-false-positive gates, severity, templates
│   ├── routing-map.md          # Target type → playbook → specialist routing
│   └── playbooks/
│       ├── a-web-api.md        # Web/REST/GraphQL/RPC security
│       ├── b-cloud-container.md # Cloud, IAM, K8s
│       ├── c-code-review-sast.md # Source code, static analysis
│       ├── d-crypto.md         # Cryptography, TLS, protocols
│       ├── e-fuzzing.md        # Parser, codec, protocol fuzzing
│       ├── f-blockchain.md     # EVM/Solana/Cosmos/Cairo/Substrate (with offensive layer)
│       ├── g-mobile.md         # Mobile apps (APK/IPA)
│       ├── h-ai-llm.md         # LLM security, prompt injection
│       ├── i-recon-network.md  # Recon, OSINT, initial access
│       ├── j-offensive-postex.md # Exploit development, post-exploitation
│       ├── k-supply-chain-secrets.md # Dependencies, secrets, supply chain
│       └── m-defense-detection.md # Blue team, detection, IR
```

## Usage

### Auto-trigger
The skill auto-triggers on requests like:
- "audit a smart contract"
- "pentest this API"
- "red-team my cloud account"
- "break this contract to its limits"
- "find DeFi vulnerabilities"
- "security test this app"

### Manual trigger
```
/viktor-blackhat
```

Then describe the target and the skill routes you to the appropriate playbook and specialist skills.

## Specialist Skills Integration

Viktor Blackhat orchestrates 100+ specialist skills including:

**Web/API:** owasp-audit, web-pentest, api-audit, 09-web-security, insecure-defaults, security-payloads, security-webshells

**Cloud:** cloud-audit, iam-audit, 10-cloud-security, exploiting-cloud-platforms, secrets-audit

**Blockchain:** solana-rust-deep-audit, web3-blockchain, entry-point-analyzer, dimensional-analysis, token-integration-analyzer, spec-to-code-compliance, plus per-chain scanners (solana-vulnerability-scanner, cosmos-vulnerability-scanner, cairo-vulnerability-scanner, substrate-vulnerability-scanner, ton-vulnerability-scanner, algorand-vulnerability-scanner)

**Code review:** owasp-audit, codeql, semgrep, c-review, variant-analysis, differential-review, trailmark-structural

**Crypto:** crypto-audit, 13-crypto-analysis, constant-time-analysis, wycheproof, zeroize-audit

**Fuzzing:** security-fuzzing, harness-writing, coverage-analysis, address-sanitizer

**Exploitation:** 03-exploit-development, vuln-research, 04-reverse-engineering

**Post-engagement:** fp-check (false-positive gate), finding-triage (disposition + severity), second-opinion (adversarial re-audit)

## Web3 Toolkit Reference

For web3/smart-contract auditing specifically, see the detailed web3 tool stack:

- **EVM/Solidity:** Slither, Foundry (forge fuzz + mainnet fork), Aderyn, Echidna, Medusa, Halmos, Certora Prover, Mythril, HEVM
- **Solana/Anchor:** Trident (stateful fuzzing), cargo-audit, cargo-geiger, solana-lints, proptest
- **Exploit PoCs:** DeFiHackLabs (real hack reproductions), Foundry fork testing, mainnet-fork PoCs
- **Formal verification:** Halmos (symbolic execution over Foundry tests), Certora CVL, Kontrol
- **Learning/Reference:** Cyfrin Updraft, Solodit (vulnerability DB), public audit reports

## Example: DeFi Protocol Audit

```
Target: EVM-based lending protocol (Solidity)

1. Skill routes to f-blockchain.md → EVM/Solidity playbook
2. Methodology (6 phases):
   - Recon: Detect languages, layout, dependency versions
   - Entry-point map: List all state-changing functions
   - Dependency check: cargo audit, npm audit
   - Parallel hunt: Account model, DeFi economics, off-chain services
   - Dimensional analysis: Annotate arithmetic units (D18{tok}, D6{usd})
   - Token integration: Check weird-ERC20 patterns
   - Structural analysis: Upgrade authority, proxies, invariants
   - Fuzz: Invariant fuzzing for broken economic properties
   - PoC: Foundry fork with profit calculation
   - Report: Severity-graded findings with fixes

3. Offensive layer:
   - Flash-loan + oracle → can I move the price and settle at manipulation?
   - Rounding → can I loop the error to drain value?
   - First-depositor inflation → can value reach the vault outside accounting?
   - Profit = extracted − flash_fee − slippage − gas; if positive → CRITICAL

4. Specialists invoked:
   - slither (fast SAST pass)
   - echidna / medusa (property-based fuzzing)
   - foundry (mainnet fork PoCs)
   - halmos (formal verification for key invariants)
   - fp-check (kill false positives)
   - finding-triage (disposition & severity)
```

## Development & Contribution

This skill is maintained and extended for your own security testing workflows. To customize:

1. Clone the repo
2. Edit playbooks or add new references
3. Update persona-and-principles.md if you want to adjust operating principles
4. Push back to your fork or create a PR

## License

This skill is provided as-is for authorized testing only. Use only on systems you own or have explicit written authorization to test.

## Author

**Viktor** — v1ktorrr0x on GitHub

Built for web3 auditors, security researchers, red teamers, and anyone who wants to break systems they own to make them stronger.

---

**Remember:** Blackhat depth, whitehat rules. The authorization gate is not a suggestion. Every finding must be proven before reporting. The goal is a stronger system, not a clever report.
