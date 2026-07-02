# redteam-master — Verification & Reporting

The "no hallucinated findings" core. A finding does not exist until proven with a concrete trigger/PoC or a traced source→sink data flow. Pattern recognition is a lead, not a finding. Pair every confirmed finding with a fix.

---

## 1. Anti-False-Positive Discipline

LLMs are biased toward seeing bugs and overrating severity. Run every suspected bug through this gauntlet before you report it.

### 1.1 Restate the claim (Step 0)

Before any analysis, restate the bug in your own words. Half of false positives collapse here — the claim stops making sense when stated precisely. Document:

- **Vulnerability claim** — exact, specific (e.g. "heap overflow in `parse_header()` when `content_length > 4096`").
- **Root cause** — the missing/broken guard, with `file:line`.
- **Trigger** — the concrete input/action that reaches it.
- **Impact** — RCE / privesc / info disclosure / DoS — be precise.
- **Threat model** — privilege level the code runs at, sandbox, what the attacker can already do *before* triggering this. ("Unauthenticated remote" vs "privileged local"; "inside renderer sandbox" vs "as root".)
- **Bug class** — pick the verification profile (memory, logic, race, integer, crypto, injection, info-disclosure, DoS, deserialization).
- **Execution / caller / architectural context** — when is this path reached, what constraints do callers impose, is there a secondary check elsewhere.

If you cannot restate it clearly, you do not understand it — stop and gather context.

### 1.2 Trace source → sink

Never analyze the sink in isolation. Trace data from entry point to the dangerous operation:

- Map every trust boundary crossed (untrusted external vs trusted internal).
- Identify all validation/sanitization between source and sink — and whether it actually prevents the claimed condition.
- Check API contracts (many APIs have built-in bounds protection) and environment protections (compiler, runtime, OS, framework). Distinguish "prevents exploitation entirely" from "raises the bar" (ASLR/canaries raise the bar; they do not debunk the bug).

**Key pitfall:** upstream conditional logic may make the sink mathematically unreachable. `buffer[length-4]` looks unsafe, but if the path is only reached when `length > 12`, the access is safe.

### 1.3 Devil's advocate

Before the verdict, argue against yourself. **Against the bug:** am I pattern-matching on scary-looking code? assuming attacker control over trusted/internal data? confusing defense-in-depth failure with a primary control? Did I prove the math, or assume it? Am I hallucinating this? **For the bug (false-negative protection):** am I dismissing it because the exploit "seems unlikely"? Am I inventing mitigations I never confirmed in the source — re-read the code after concluding.

### 1.4 Rationalizations to reject

If you catch yourself thinking any of these, STOP.

| Rationalization | Why it's wrong | Required action |
|---|---|---|
| "Rapid analysis of remaining bugs" | Every bug gets full verification | Verify the next bug through all phases |
| "This pattern looks dangerous, so it's a vuln" | Pattern recognition is not analysis | Complete data-flow tracing first |
| "Skipping full verification for efficiency" | No partial analysis allowed | Execute all steps on the chosen path |
| "Code looks unsafe, report without tracing" | Unsafe-looking code may have upstream validation | Trace the full source→sink path |
| "Similar code was vulnerable elsewhere" | Each context has different callers/guards | Verify this instance independently |
| "This is clearly critical" | LLMs overrate severity | Prove it with evidence; run devil's advocate |

### 1.5 Routing — standard vs deep

**Standard** (linear, single-pass, no task tracking) when ALL hold: clear specific claim; single component; well-understood bug class; no concurrency in the trigger; straightforward data flow.

**Deep** (task-tracked phases, one task per phase with dependencies) when ANY hold: ambiguous claim; cross-component path (3+ modules/services); race/TOCTOU/async in the trigger; logic bug with no clear spec; standard was inconclusive; full verification requested.

Default to standard. It has two escalation checkpoints — after data-flow (3+ trust boundaries, async/callbacks, ambiguous validation) and after devil's advocate (any unresolved uncertainty) — that route to deep. When escalating, hand off all evidence gathered; do not repeat completed work.

### 1.6 Six gates → verdict

All six must PASS before you report a bug. Any FAIL → FALSE POSITIVE.

| Gate | Pass criterion |
|---|---|
| **1. Process** | Every phase has documented evidence |
| **2. Reachability** | Attacker-controlled path to the sink, confirmed by PoC |
| **3. Real Impact** | Leads to RCE / privesc / info disclosure (not just an operational robustness issue) |
| **4. PoC Validation** | PoC (pseudocode, executable, or unit test) shows control + trigger + impact |
| **5. Math Bounds** | Algebraic proof the vulnerable condition is possible |
| **6. Environment** | No environmental protection entirely blocks exploitation |

**Verdict format** (state evidence, never a bare label):

```
BUG #N TRUE POSITIVE — [brief vulnerability description]
BUG #N FALSE POSITIVE — [gate that failed + evidence]
```

Example: `BUG #3 FALSE POSITIVE — integer underflow in packet_handler.c:142. Gate 5 FAIL: validation at line 98 ensures packet_size >= 16, so (packet_size - header_size) >= 8. Underflow impossible.`

When batch-triaging: restate all claims first (collapses obvious FPs), route each independently, process standard before deep, then check whether individually-failed findings combine into an **exploit chain**.

---

## 2. Severity & Triage

### 2.1 Confidence

- **Confirmed** — a working PoC or a complete traced source→sink data flow.
- **Potential** — an unverified lead. State exactly what evidence is still missing to confirm it. Never report a Potential as Confirmed.

### 2.2 Contextual severity

The scanner's CVSS is a starting point, not the answer. Adjust for your environment. **Raises** severity: internet-facing; easy-to-satisfy auth precondition (open signup); regulated data (PII/PCI/PHI); public PoC or active exploitation; component on the critical path. **Lowers** severity: code path unreachable in your usage; strong compensating control (WAF, segmentation); precondition absent in your env; dev/build-only, not runtime-reachable.

| Level | Definition / SLA |
|---|---|
| **Critical** | Pre-auth or trivial; immediate RCE / data loss / takeover; fix 24–72h |
| **High** | Auth required but low privilege, or post-auth path to significant impact; fix 1–2 weeks |
| **Medium** | Needs meaningful privilege or a chain; realistic but not trivial; fix 30 days |
| **Low** | Defense-in-depth; hard to chain; fix 90 days |
| **Info** | Hardening / hygiene; fix when convenient |

Calibrate to evidence and reachability, not to how scary the pattern looks. Justify the rating.

### 2.3 Dispositions

| Disposition | When | Required fields |
|---|---|---|
| **Fixed** | Remediation deployable within the severity SLA | Fix description, deploy plan, verification method |
| **Deferred** | Action warranted but immediate fix infeasible | Reason, new deadline, owner, escalation trigger. **Severity does not change** — downgrading a High because the deadline is far is risk-laundering |
| **Accepted Risk** | Fix not planned at current config | (1) why the fix doesn't apply, (2) compensating controls, (3) re-evaluation trigger |
| **False Positive** | Not a real finding | Evidence for the determination + scanner rule ID to suppress (with care) |

An **Accepted Risk** missing any of its three fields is a real finding silently dropped under a label. The re-evaluation trigger is the most-skipped — name a concrete condition (plan upgrade, dependency bump, traffic-pattern change, audit anniversary). Escalate to a second reviewer: anything Critical, pre-auth, regulated-data, public-PoC, or Accept-Risk on High+.

---

## 3. Report Format

For every category audited, record one of three states — credibility comes from proving you looked:

- **Finding** — with severity + remediation.
- **Clean** — "Checked X for Y, found no issue" (state what you grepped/traced).
- **N/A** — why the category doesn't apply.

### 3.1 Per-finding template

```markdown
#### [SEVERITY] [Confirmed|Potential] — [Title]
**File:** `path/to/file.ts:42`
**CWE:** CWE-XXX

**Description:** [what the vulnerability is and why it matters]

**Vulnerable Code:**
[snippet]

**PoC / Verification:** [exact input, exact code path, precondition (privilege/auth/config),
observed effect. Defang live payloads — describe the mechanism, redact the weaponized body,
reference the source file path instead of pasting it.]

**Remediation:**
[fixed code + explanation]

**Verification of fix:** [concrete adversarial input + the command/path that proves the fix
holds. The off-host URL that now rejects; the 1-char password that now fails to save; the
script-breakout payload that no longer breaks out. "The linter says it's fine" is NOT
verification — static analysis has blind spots for exactly these bugs.]
```

### 3.2 Executive summary

```markdown
# Security Audit Report
## Project: [name]
## Stack: [technologies]
## Date: [date]

### Summary
- Total findings: X
- Critical: X | High: X | Medium: X | Low: X | Info: X

### Items checked and found clean
- [Category / pattern checked, with what was grepped/traced, found no issue]

### Findings
[individual findings as above]

### Prioritized Remediation Plan
1. [Critical — immediate]
2. [High — this week]
3. [Medium/Low — scheduled]
```

The "Items checked and found clean" section is mandatory. Silence is not coverage — say where you looked and what you did not test (out of scope / no access).

---

## 4. Responsible Disclosure & Comms

Findings are findings, not ammunition — you report to fix systems, never to surveil or punish a person.

- **Match the register to the audience.** Same finding, different drafts: file paths/CWE/repro for engineers; dollar/percentage impact and the decision-needed for executives; "did my data get accessed, what do I do" for customers. Using the wrong register is the most common failure mode.
- **Lead with the takeaway.** Write what the reader keeps if they read only the first paragraph, then back into detail. Boards want the punchline, not a 30-row CVE table.
- **Quantify where possible**, even roughly ("affects ~8% of paying customers" beats "some customers"). If you don't know, say so — don't hedge with weasel words.
- **Cut evasive softeners.** "Out of an abundance of caution," "best efforts," "industry-standard" read as evasive. State concretely what was found, what was done, what's next, with names attached.
- **Disclosure has legal teeth.** Customer-facing breach notices touch GDPR Art. 33 (72h to the authority), HIPAA Breach Notification (60 days), state laws, and SEC 8-K for material incidents at public companies. This skill produces a *draft*; legal/counsel review before it ships. A draft is not a sent message.
- **Refuse to mislead.** Do not downplay material impact, attribute blame falsely, or label an Accepted-Risk finding "resolved." AI-drafted comms are a first draft, not the final — keep the human review loop for the named audience.

---

## 5. Second Opinion

A single pass catches checklist categories but misses the bypasses not *on* the checklist. After the first report — and again after applying fixes — run a second adversarial pass ("assume the author is overconfident; find what they missed"), ideally with a different model/agent to break correlated blind spots. Treat any disagreement as the higher-value finding. Watch specifically for: new attack surface introduced by the fix (auth bypass via an exempted route, IDOR from a new query); stale comments; boundary conditions in new code (env-unset fallthrough, empty input); and library-config fixes that are correct but never run on your code path — trace from your call site to the code the config actually affects.
