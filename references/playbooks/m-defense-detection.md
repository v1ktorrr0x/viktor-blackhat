# Defense, Detection, IR & Compliance Playbook

The post-engagement half of a whitehat's job: after you broke in, you advise the
blue team on how to *detect, respond to, and prevent* what you just did — and how
to prove it to auditors. This playbook distills detection engineering, threat
hunting, IR/forensics, malware triage, OT/ICS defense, and GRC/privacy mapping
into one cross-referenced methodology. Authorized work only; everything here is
remediation- and defense-framed.

> **AV-safety note:** This file describes detection *logic* and defangs every
> sample. Live payload bodies, webshells, and reverse-shell one-liners are
> referenced by source-file path, never pasted. Keep it that way when you extend
> this playbook.

## When this applies

Route an engagement here when the deliverable is *defensive*, not offensive:

- "We got popped — what now?" → incident triage, evidence preservation, scoping.
- "Write detections for the TTPs you used / a threat report" → Sigma/KQL/SPL/EQL,
  YARA, Suricata.
- "Hunt for an adversary already inside" → hypothesis-driven hunting (PEAK/TaHiTI).
- "Triage this suspicious binary / sandbox report" → static + dynamic malware analysis.
- "Run / improve our SOC" → triage workflow, runbooks, escalation, MTTD/MTTR KPIs.
- "Harden us after the red team" → CIS baselines, Sysmon, detection-as-code.
- "Assess our OT/ICS plant" → Purdue model, passive protocol analysis, IEC 62443.
- "Map us to CSF / PCI / HIPAA / GDPR" → control crosswalk, gap analysis, breach clocks.

Signal words: SIEM, Sigma, YARA, ATT&CK, IOC, hunt, beaconing, LOLBin, IR,
PICERL, Volatility, chain of custody, ransomware, CSOC, MTTD/MTTR, Sysmon, CIS,
Purdue model, Modbus/DNP3, IEC 62443, NIST CSF, PCI DSS, PHI/ePHI, DSAR, GDPR.

## Methodology

The post-engagement defense lifecycle, in order:

1. **Triage & classify (if live incident).** Determine type (malware /
   unauthorized access / exfil / web compromise / phishing) and severity. Priority
   order is fixed: human safety → contain → preserve evidence → scope → document
   (incident-triage). Never power off — volatile memory is evidence; network-isolate
   instead.
2. **Preserve evidence by order of volatility.** CPU/cache → RAM (capture FIRST) →
   network state → running procs/open files → disk → logs → media. Hash every
   artifact, log chain of custody (07-incident-response).
3. **Analyze artifacts.** Memory forensics (Volatility), disk forensics (Sleuth
   Kit), malware static/dynamic triage. Extract IOCs and map behaviors to MITRE
   ATT&CK technique IDs.
4. **Build the timeline.** Normalize all timestamps to UTC, fuse log sources into a
   supertimeline, reconstruct the kill chain (delivery → exec → C2 → lateral →
   exfil → impact).
5. **Hunt for spread.** Take the IOCs/TTPs and pivot environment-wide with a
   *specific, testable, bounded* hypothesis (PEAK). Confirm/deny, escalate hits.
6. **Engineer detection-as-code.** Convert every confirmed finding into a versioned
   Sigma rule (then convert per-backend), YARA rule, or correlation rule, each with
   ATT&CK tags, false-positive notes, and a tested sample event.
7. **Harden & prove the fix.** Map findings to CIS/baseline hardening; pair every
   hardening change with the detection that catches its bypass (15-blue-team-defense).
8. **Map to governance.** Translate technical findings into CSF/PCI/HIPAA/GDPR
   control language; start regulatory breach clocks where personal/health/card data
   is in scope.

## High-signal checklist

### Malware triage (05-malware-analysis)
- Hash first: SHA-256 primary identifier; MD5/SSDeep for lookups. SSDeep similarity
  > 70% ⇒ same family/variant.
- **Entropy gate:** section entropy 7.0–8.0 ⇒ packed/encrypted — investigate; 7.9–8.0
  ⇒ likely encrypted payload. Do not write string rules against packed layers — the
  packing changes, the payload doesn't.
- **Suspicious import clusters** (PE static): process injection (`CreateRemoteThread`,
  `WriteProcessMemory`, `VirtualAllocEx`, `NtMapViewOfSection`); anti-analysis
  (`IsDebuggerPresent`, `GetTickCount`); credential access (`LsaOpenPolicy`,
  LSASS read); keylogging (`SetWindowsHookEx`, `GetAsyncKeyState`).
- **Behavioral red flags:** `vssadmin delete shadows` (T1490 ransomware), Office →
  PowerShell/cmd parent-child chains, beaconing at regular intervals, LSASS access
  (T1003.001).
- **2026 landscape:** infostealers + loaders dominate; watch BYOVD/EDR-killers,
  direct/indirect syscalls, AMSI/ETW patching, fileless/reflective .NET loads. For
  AI-generated samples (low shared code) prefer behavioral + YARA-on-behavior over
  hash matching.
- **Safety:** detonate only in isolated, snapshot-restored VM, host-only network,
  INetSim/FakeNet, shared folders/clipboard off. Document the sandbox config in the report.

### YARA authoring (yara-rule-authoring — YARA-X)
- **String tiers:** Gold = mutex names, stack strings, PDB paths (almost always
  unique); Silver = C2 paths, config markers; Bronze = unique error messages,
  campaign IDs. Reject API names, common paths (`cmd.exe`), format strings (`%s`).
- **Atom rule:** strings must yield good 4-byte atoms. <4 bytes or repeated bytes
  (`0000`, `9090`) force slow bytecode verification on every file.
- **Condition short-circuit order:** `filesize <` → magic bytes (`uint16(0)==0x5A4D`
  for PE) → string matches → module checks (expensive). If >5 lines, split the rule.
- **`any of` vs `all of`:** `any of` only when each string is *individually* unique;
  common strings + `any` = FP flood (production lesson: `any of ($network_*)` with
  "fetch"/"axios" matched every web app — fix was require credential-path AND
  network-call AND exfil-destination together).
- **Regex must be anchored** to a 4+ byte literal substring, else it evaluates at
  every file offset (catastrophic). Bound all quantifiers: `.{0,30}` not `.*`.
- **Modifier discipline:** never use `nocase`/`wide` speculatively — each has real
  cost (nocase doubles atoms; wide doubles matching). Only with confirmed evidence
  the case/encoding varies.
- **Naming:** `{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}` (e.g.
  `MAL_Win_Emotet_Loader_Jan25`). Required meta: description (starts "Detects"),
  author, reference, date.
- **Goodware test before deploy:** `yr scan -s` against a clean corpus; 1-2 goodware
  hits ⇒ tighten, 3-5 ⇒ different indicators, 6+ ⇒ start over.
- When strings fail (only API names), pivot to structure: `pe.imphash()`, section
  names/sizes, `math.entropy()` on sections.

### Threat hunting (06-threat-hunting, threat-hunting)
- **Hypothesis must be specific, testable, bounded** — names a technique, a log
  source, an expected artifact, and a time window. "Look for anomalies" is not a hunt.
- **High-yield hunts:**
  - Persistence: Run-key writes (Sysmon EID 13 to `...\Run`), scheduled tasks (4698)
    or service install (7045) outside install windows, WMI `__EventFilter` +
    `CommandLineEventConsumer` subscriptions.
  - Defense evasion: PowerShell `-EncodedCommand` (evasion ~80% of the time),
    `certutil -decode`, exec from `%TEMP%`/`%APPDATA%`/`\Users\Public`.
  - Credential access: LSASS access (Sysmon EID 10, TargetImage=lsass.exe) from
    unexpected SourceImage; `comsvcs.dll` minidump; Kerberoast prep (4769 + RC4).
  - Lateral: PsExec/remote service create with random service name, WMI to remote
    hosts, one SSH key authenticating to many hosts in a short window.
  - Cloud/identity: IMDS hit (`169.254.169.254`) from non-SDK process, CloudTrail
    `StopLogging`/`DeleteTrail`, impossible-travel sign-ins, OAuth high-scope consent
    grants, MFA enrollment from new device (session-theft persistence).
- **Every hunt yields an artifact:** a detection rule (if found), a documented
  dead-end (if not), or a logged coverage gap. Hunts without artifacts are
  non-compounding work.
- Confirmed-malicious ⇒ escalate to IR immediately; do not keep hunting and tip the adversary.

### Detection engineering (12-log-analysis, siem-detection, 15-blue-team-defense)
- **Map log sources to ATT&CK coverage FIRST.** Techniques with no source mapped are
  blind spots. Common gaps: command-line args not captured (Win default logs binary
  only — enable 4688 cmdline / `ProcessCreationIncludeCmdLine_Enabled`), CloudTrail
  `ReadOnly` events filtered (recon invisible), no SaaS audit logs.
- **Match detection model to threat:** known IOC ⇒ intel lookup; known pattern ⇒
  signature; behavior outside baseline ⇒ statistical/UEBA; event sequence ⇒
  correlation; novel ⇒ hunt.
- **Write canonical rule in Sigma**, auto-convert per backend (`sigma convert -t
  splunk|kusto|elasticsearch`). Even single-SIEM shops benefit.
- **Critical Windows event IDs:** 4624/4625 (logon success/fail — Type 3 = network),
  4648 (explicit creds), 4688 (process create), 4698 (sched task), 4720 (user
  created), 4768/4769 (Kerberos TGT/TGS), 5140/5145 (share access), 7045 (service
  install), 1102 (audit log cleared — high signal), 4103/4104 (PowerShell script
  block).
- **Crown-jewel SIEM detections:** brute-force→success join, Pass-the-Hash (4624
  Type 3 + NTLM), DCSync (4662 with replicating-directory-changes GUID
  `1131f6ad-...` from non-DC account), Kerberoasting (4769 enc type `0x17`/RC4),
  LSASS dump (Sysmon EID 10 not from System32/Program Files), impossible travel.
- **FP lifecycle:** deploy `experimental` 1-2 weeks → triage every fire → narrow or
  allow-list → promote to `high` only when FP rate acceptable. FPs >80% after tuning
  ⇒ wrong detection model. Rules that never fire ⇒ broken coverage or broken query —
  verify with a deliberate test event.
- **Detection-as-code:** rules in Git, each with ATT&CK tag, description, references,
  `falsepositives`, tested positive/negative sample events; CI lints + converts +
  replays before deploy. Track ATT&CK coverage as a measurable metric (DeTT&CT-style).
- Normalize sources to OCSF/ECS so one detection works across feeds.

### Incident response & forensics (07-incident-response, incident-triage, disk-forensics)
- **PICERL:** Preparation → Identification → Containment → Eradication → Recovery →
  Lessons Learned (NIST SP 800-61).
- **Memory forensics (Volatility 3):** `windows.pstree` (parent-child), `windows.psscan`
  (hidden procs), `windows.malfind` (injected code), `windows.hollowfind` (hollowing),
  `windows.netscan`. Red flags: process with no disk file, network conns from
  lsass/csrss, `svchost.exe` with unusual parent.
- **Disk forensics:** work on copies only, mount read-only, verify hash before
  analysis. `mmls` (partitions), `fls -r` (deleted files marked `*`), `icat` (extract
  by inode), `mactime` (timeline), `bulk_extractor`/`foremost` (carving). Flag
  timestamps before OS install, future-dated files, gaps in continuous logs.
- **Timeline anomalies = kill chain.** Build supertimeline (plaso/log2timeline,
  Hayabusa/Chainsaw over EVTX), normalize UTC, identify Patient Zero.
- **Cloud/identity IR (2026):** pull CloudTrail / Entra sign-in+audit / GCP audit;
  preserve volatile cloud state (snapshots, disable IAM keys) before remediation;
  revoke sessions/refresh tokens, rotate signing keys, review conditional access.
- **Ransomware specifics:** look for exfil-before-encrypt (double extortion),
  ESXi/Linux scope, validate recovery against *immutable* backups.

### SOC operations (11-csoc-automation, soc-operations)
- **Triage matrix:** confidence × asset criticality → action + SLA. High+Critical ⇒
  immediate escalation/incident (15 min). Low+any ⇒ auto-close with documentation.
- **Runbook every alert that fires >2-3 times.** Structure: plain-English meaning,
  common FPs/TPs, triage steps, decision point, escalation target. Lives in version
  control, not Slack DMs.
- **KPIs that matter:** MTTD (<1hr behavioral), MTTR, MTTC (<1hr confirmed
  compromise), TP rate per rule (>30% or tune/kill), alerts/analyst/shift (<25 before
  fatigue dominates), runbook coverage (>80% of volume).
- **Alert-fatigue diagnostic:** analysts closing alerts in <30s, repeated
  un-suppressed ignores, turnover >25%/yr, "fired but not actioned" post-mortems.
  Remedy: full-stop new-rule pipeline, spend a cycle tuning.
- **AI-assisted triage** with a human-in-the-loop gate before any containment;
  irreversible actions require explicit human approval; log every automated action.

### OT/ICS defense (18-ot-ics-security)
- **Safety is the first constraint.** Default to passive (SPAN/TAP, PCAP) — a crashed
  PLC means equipment damage or loss of life. No active scans/writes/fuzzing on prod
  OT without written authorization, asset-owner sign-off, and a tested rollback.
- **Purdue model flags:** missing IDMZ (L3.5), flat IT/OT networks, dual-homed
  engineering workstations, vendor remote access bypassing DMZ, any direct L4/L5 →
  L0-L2 path.
- **Protocol watch (most have no auth/encryption by design):** Modbus/TCP (502) write
  function codes 5/6/15/16; DNP3 (20000) operate/direct-operate without SAv5; S7comm
  (102) PLC start/stop, program up/download; EtherNet/IP+CIP (44818) forward-open;
  OPC-UA (4840) security policy `None`/anonymous.
- **ATT&CK for ICS** key techniques: T0883 (internet-accessible device), T0836
  (modify parameter), T0831 (manipulation of control), T0814 (DoS), T0816 (device
  restart/shutdown). Anchor scenarios to Stuxnet, TRITON/TRISIS (targets SIS),
  Industroyer, PIPEDREAM/INCONTROLLER.
- **IEC 62443:** define zones & conduits, assign Security Levels SL 1-4; review FR1-FR7.
- **OT IR inversion:** safety and process continuity *outrank* evidence preservation;
  involve process/safety engineers; have a manual-operations fallback before isolating.

### GRC & compliance mapping (19-grc-compliance, csf-mapping, pci-audit, hipaa-audit, privacy-engineering)
- **NIST CSF 2.0 functions:** Govern, Identify, Protect, Detect, Respond, Recover
  (Govern added in 2.0). Tiers 1-4: Partial / Risk-Informed / Repeatable / Adaptive.
  Refuse to inflate tiers without evidence — Tier 3 = "evidence of documented
  org-wide processes," not aspiration.
- **Cross-framework reuse:** one control statement mapped to many frameworks (CSF ↔
  ISO 27001:2022 Annex A ↔ SOC 2 TSC ↔ 800-53 ↔ PCI ↔ CIS v8) so one piece of
  evidence satisfies many obligations.
- **PCI DSS v4.0 — scope is the leveraged variable.** Trace every PAN flow
  end-to-end; everything the PAN touches (and connected-to/security-impacting systems)
  is in scope. Reduce scope via hosted payment page / tokenization / P2PE /
  segmentation. Engineering reqs: Req 3 (never store CVV/track data; mask PAN; encrypt
  at rest), Req 4 (TLS 1.2+, no PAN over email/SMS), Req 6 (secure SDLC), Req 8 (MFA
  into CDE — new in v4.0), Req 10 (log all CHD access, 12-month retention), Req 11
  (quarterly ASV scans, annual pentest + segmentation test).
  - **Audit greps (defanged):** schema columns `pan`/`card_number`/`cc_number`; PAN
    regexes by brand (Visa `^4[0-9]{12,15}$`, MC `^5[1-5][0-9]{14}$`, Amex
    `^3[47][0-9]{13}$`); logs `log.*cardNumber`; confirm Sentry/Datadog scrubbing of
    Luhn-valid sequences. Any Luhn-valid PAN in source/logs/locks = a finding.
- **HIPAA — ePHI scope is broader than expected** (an IP + health condition can be
  PHI). 18 Safe-Harbor identifiers; pseudonymized data is *still* PHI. Security Rule
  technical safeguards: §164.312(a) unique IDs + emergency access + auto-logoff +
  encryption at rest; (b) audit controls (6-year retention); (d) authentication (treat
  MFA as effectively required); (e) transmission encryption. Greps: shared-account
  `SELECT.*patient`, `SELECT *` on PHI tables (minimum-necessary violation), PHI to
  non-BAA vendors (Mixpanel by default has no BAA).
- **Breach clocks (start when *anyone* on the team becomes aware):** GDPR 72 hours to
  supervisory authority; HIPAA 60 days to individuals/HHS (≥500 also media);
  PCI acquirer notification typically within 24 hours. Encryption with separated keys
  is the breach safe harbor for HIPAA/GDPR.
- **Privacy (GDPR/CCPA):** build for the strictest regime (GDPR). Crown-jewel
  engineering: data classification, minimization (truncate IP to /24, store age-bool
  not DOB), lawful-basis log, consent records (withdrawal as easy as granting — Art
  7(3)), and the **DSAR deletion fan-out** (primary DB → replicas → backups → caches →
  search indexes → analytics → warehouse → logs → every sub-processor). Greps for
  PII exfil destinations: `analytics.track`, `Sentry.setUser`, `mixpanel.people.set`,
  `LogRocket.init`, `FullStory.init` — each is a deletion-fanout target.

## Tools & commands

Only tools/flags named in the sources.

- **Malware:** `file`, `sha256sum`, `ssdeep` (`-l`/`-m`), `strings -a`, `yara -r`,
  YARA-X `yr scan -s` / `yr check` / `yr fmt` / `yr dump -m pe`, yarGen
  (`-m samples/ --excludegood`), FLOSS, DIE, pestudio, VirusTotal API.
- **Sandbox/dynamic:** Cuckoo/CAPE, INetSim/FakeNet-NG, Process Monitor, Regshot,
  Autoruns, Wireshark, MalwareBazaar/Triage/Hybrid Analysis.
- **Memory/disk forensics:** Volatility 3 (`windows.pslist`/`pstree`/`psscan`/
  `netscan`/`malfind`/`hollowfind`/`registry.printkey`), winpmem, avml/LiME, KAPE,
  Velociraptor, Sleuth Kit (`mmls`/`fsstat`/`fls -r`/`icat`/`mactime`),
  foremost/scalpel, bulk_extractor, exiftool, ewfinfo, Hayabusa/Chainsaw, plaso.
- **SIEM/detection:** Splunk SPL (`tstats`, `bin`, `transaction`), Microsoft Sentinel
  KQL (ASIM, `serialize`/`prev()`), Elastic EQL/ES|QL (`sequence by ... with maxspan`),
  QRadar AQL, Sigma + `sigma convert`/`sigma-cli check`, python-evtx, Suricata/Snort.
- **Hardening:** Sysmon (SwiftOnSecurity/Olaf config), auditd, Lynis, OpenSCAP/oscap,
  CIS-CAT, fail2ban, AppLocker/WDAC, `auditpol /set /subcategory`,
  `Set-SmbServerConfiguration -EnableSMB1Protocol $false`, Falco/Tetragon (eBPF).
- **OT/ICS:** `tshark` with ICS dissectors, nmap read-only NSE (`modbus-discover`,
  `s7-info`, `bacnet-info`, `enip-info`), GRASSMARLIN, Shodan/Censys dorks
  (`port:502 product:Modbus`).
- **GRC:** ATT&CK Navigator, MITRE D3FEND, sigma-cli; STIX 2.1 / TAXII / MISP /
  OpenCTI for IOC sharing.

## Expert gotchas / bypasses

- **Don't power off a live host** — RAM is evidence; network-isolate instead
  (incident-triage, 07-incident-response).
- **Don't write YARA against packed layers** — entropy >7.0 means find the unpacked
  payload first; the packing changes, the payload doesn't (yara-rule-authoring).
- **`any of` + common strings = FP flood.** The single biggest YARA mistake. Require
  the *combination* (credential path AND network AND exfil destination).
- **A rule that never fires is a finding,** not a success — it usually means broken
  log coverage or a wrong query. Replay a deliberate test event to tell which.
- **Scope determines everything in PCI** — most failures are scope failures. A
  surrogate token reversible by your processor account is still in scope; only one-way
  tokens reduce it. "Hosted payment page" via server-side proxy still touches the PAN
  (in scope); a true iframe does not (out of scope).
- **Pseudonymized ≠ anonymized.** Internal pseudonyms are still ePHI/personal data
  because the linking table exists. De-identification (Safe Harbor / Expert
  Determination) is the only way out of PHI scope (hipaa-audit, privacy-engineering).
- **The breach clock starts at first awareness by *anyone* on the team** — your
  detection-to-leadership latency directly burns the 72-hour/60-day window. Audit logs
  are the source of truth for fast scoping (privacy-engineering, hipaa-audit).
- **OT inverts IR priorities:** safety/process continuity outrank evidence
  preservation; never isolate without a manual-operations fallback (18-ot-ics-security).
- **Pair every hardening change with the detection that catches its bypass** — a
  control without a detection is unverifiable (15-blue-team-defense).
- **Detection-as-code or it didn't happen:** a rule without ATT&CK tag, FP notes, and
  a tested sample event will produce alert fatigue and get ignored
  (siem-detection, 12-log-analysis).
- **Hunt artifacts compound; one-off hunts don't.** Turn every hunt into a rule, a
  documented dead-end, or a coverage-gap backlog item (threat-hunting).

## Delegate to

Invoke these specialist source skills via the Skill tool for a full-depth pass:

- **05-malware-analysis** — use when triaging a suspicious binary/script, extracting
  C2 config, or generating YARA from samples (full PE/entropy/import tables, sandbox setup).
- **yara-rule-authoring** — use when authoring/optimizing/debugging YARA-X rules
  (atom theory, crx/dex modules, FP investigation, goodware validation).
- **06-threat-hunting** — use for IOC extraction/normalization, STIX/ATT&CK Navigator
  layers, and SIEM hunt-query libraries.
- **threat-hunting** — use for PEAK/TaHiTI hypothesis-driven hunts with the high-yield
  hunt catalog and pivot patterns.
- **07-incident-response** — use for full PICERL playbooks, Volatility command sets,
  chain-of-custody templates, and post-incident reports.
- **incident-triage** — use for fast first-response triage and the volatility-ordered
  evidence-capture commands.
- **disk-forensics** — use for disk-image analysis, deleted-file recovery, carving,
  and forensic timeline construction.
- **12-log-analysis** — use for SIEM query building (SPL/KQL/EQL/AQL), Sigma rules,
  correlation rules, and log-source health.
- **siem-detection** — use for detection-engineering programs: log-source→ATT&CK
  coverage mapping, FP tuning lifecycle, detection-as-code CI.
- **11-csoc-automation** — use for SOAR-compatible playbooks, escalation workflows,
  shift handovers, and SOC KPI dashboards.
- **soc-operations** — use to build/run/improve a SOC: staffing math, tiering,
  runbook authoring, alert-fatigue remediation.
- **15-blue-team-defense** — use for CIS hardening (Linux sysctl/auditd, Windows
  Sysmon/audit policy), detection engineering, and post-red-team remediation plans.
- **18-ot-ics-security** — use for any OT/ICS/SCADA assessment: Purdue map, passive
  protocol analysis, IEC 62443 zone/SL, ATT&CK-for-ICS.
- **19-grc-compliance** — use for risk registers, cross-framework control crosswalks,
  gap analysis, SoA, and policy drafting.
- **csf-mapping** — use to map posture to NIST CSF 2.0 with tiers, gap analysis, and
  board-ready roadmap.
- **pci-audit** — use for PCI DSS v4.0 scope determination and per-requirement
  engineering audit.
- **hipaa-audit** — use for ePHI scoping, Security Rule safeguard audit, and breach
  notification readiness.
- **privacy-engineering** — use for GDPR/CCPA technical implementation: DSAR pipeline,
  consent, sub-processor inventory, breach scoping.
