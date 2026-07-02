# Recon, OSINT & Network Security Playbook

Distilled from `recon`, `osint-recon`, `01-recon-osint`, `initial-access-recon`, `08-network-security`.
For **authorized** engagements only — confirm written scope before any active touch. Keep the remediation framing: every finding maps to a fix.

---

## When this applies

Route an engagement here when the target signal is any of:

- A bare domain, org name, or IP/CIDR with no prior map — "enumerate," "attack surface," "asset discovery," "external footprint."
- Subdomain enumeration, DNS analysis, zone transfers, technology/stack fingerprinting.
- OSINT on a domain/org/person — digital footprint, leaked credentials, email-format discovery, document metadata.
- Initial-access recon / perimeter discovery: port scanning, service detection, banner grabbing, cloud-bucket hunting.
- A **PCAP/PCAPNG** to analyze, or a request to author **Snort/Suricata/Zeek** detections, audit **iptables/nftables/SG** rules, or hunt C2 beaconing / DNS tunneling / exfil in traffic.

This is the **front of the kill chain** (passive → active map → traffic) plus the **defensive network mirror**. Once you have an attack-surface map, hand web apps to web-pentest/owasp-audit, cloud assets to cloud-audit, services to the vuln scanner.

**Authorization gate (recon, 01-recon-osint):** confirm (1) written authorization for the target scope, (2) target is in-scope. If unclear, ask — never assume. Refuse mass scanning of unrelated targets and any OSINT aimed at harassment/doxing (osint-recon ethics check: public sources only, no PII aggregation beyond the objective).

---

## Methodology

### Phase 1 — Passive recon (no direct target contact)
1. **WHOIS + registration** — `whois <domain>` for registrant, registrar, nameservers, creation date. Flag privacy-protected registrations and registrar patterns (01-recon-osint).
2. **Certificate Transparency** — the single most effective passive subdomain source. Pull all SANs from crt.sh (command below); strip wildcards (`*`).
3. **Passive DNS** — enumerate A, AAAA, MX, NS, TXT, SOA, SRV, CNAME, CAA, PTR via public resolvers. Analyze SPF/DKIM/DMARC posture. Pull DNS history (SecurityTrails, DNSDumpster, PassiveDNS) for old infra.
4. **Search-engine & code dorking** — Google/GitHub dorks for exposed files, admin panels, config leaks, and leaked secrets (payloads below).
5. **Shodan/Censys** — internet-exposed services, banners, certs for the target's IP ranges. Pivot on favicon `mmh3` hashes and JARM/JA4S fingerprints to find sibling infra behind CDNs (01-recon-osint v3).
6. **OSINT correlation** — org filings, LinkedIn (employees, roles, tech-stack hints), job postings (internal tooling), HaveIBeenPwned + public combolists (check-only, never distribute), document metadata via `exiftool`.

### Phase 2 — Active recon (explicit authorization only)
1. **Wildcard detection first** — resolve a random subdomain (`randomnonexistent12345.<domain>`); if it answers, DNS is wildcard and brute-force results are false positives until filtered.
2. **Active subdomain discovery** — DNS brute-force (amass/gobuster/ffuf/dnsrecon) over a wordlist; attempt **zone transfer (AXFR)** on every NS.
3. **Resolve + probe** — resolve all candidates to IPs (discard NXDOMAIN), HTTP-probe 80/443 to find live web apps, group by IP/ASN to separate cloud vs on-prem.
4. **Port scan** — top-1000 first (`-sC -sV`), then full range `-p-` if warranted; UDP top-1000 separately; service-version + OS detection where authorized; banner-grab.
5. **Web content discovery** — directory/vhost/parameter brute-force, JS analysis for secrets and endpoints, `/robots.txt` `/sitemap.xml` `/.git/` `/.env` `/swagger.json` `/graphql`.
6. **Cloud asset discovery** — permute org name into S3/GCS/Azure-Blob names; check world-readable/listable buckets.
7. **Takeover check** — every dangling `CNAME` → unclaimed S3/Azure/GitHub-Pages/Heroku/Fastly target is a takeover candidate; fingerprint the orphaned service (can-i-take-over-xyz).

### Phase 3 — Fingerprint & prioritize
1. Fingerprint each live host (server, CMS, framework, language, WAF, CDN, analytics, TLS) from headers + body signatures.
2. Score the email-auth posture and flag DNS misconfigs (AXFR, weak SPF/DMARC, no DNSSEC).
3. **Separate confirmed assets (resolved + responding) from candidates (CT-log only)** and tag the discovery source per asset so findings are reproducible (01-recon-osint precision rule).
4. Prioritize by impact × likelihood × exposure (internet-facing first). Hand off to follow-on skills.

### Phase 4 — Network traffic / defensive analysis (08-network-security)
1. **PCAP triage** — protocol hierarchy, top talkers, conversations, then drill into DNS/HTTP/TLS/SMB/ICMP per the checklist.
2. **Hunt the four big patterns** — beaconing (regular intervals), DNS tunneling (long/high-volume queries), exfil (large POSTs), lateral movement (SMB/PsExec).
3. **Author detections** — write a Suricata rule *and* a Zeek detection where applicable; report each flow with the 5-tuple, JA4 fingerprint, bytes/duration, and a confidence-scored verdict.
4. **Audit controls** — review firewall rules (iptables/nftables/pf/cloud SG) and network zoning against the checklists.

---

## High-signal checklist — CROWN JEWELS (verbatim)

### Certificate Transparency (best passive subdomain method)
```bash
curl -s "https://crt.sh/?q=%25.$ARGUMENTS&output=json" | jq -r '.[].name_value' | sort -u
```
In-script form (note the `%.` URL-encoding and wildcard strip): `url = f"https://crt.sh/?q=%.{domain}&output=json"`, then split `name_value` on `\n`, keep names ending `.{domain}`, drop any containing `*` (subdomain_enum.py).

### DNS enumeration + zone transfer (recon, initial-access-recon)
```bash
dig any $ARGUMENTS                      # A/AAAA/MX/TXT/NS/CNAME in one shot
dig axfr @ns-server $ARGUMENTS          # zone transfer — full-zone exposure if it succeeds
dig AXFR @ns1.example.com example.com
host -l domain.com ns1.domain.com       # alternate AXFR
fierce --domain domain.com
```
Record types to sweep: `A, AAAA, MX, NS, TXT, SOA, SRV, CNAME, CAA, PTR` (dns_recon.py).

### Email-security misconfigs to flag (01-recon-osint, dns_recon.py)
- **No SPF** → domain spoofable. **SPF `+all`** → any server can send as the domain. `~all` (softfail) / `?all` (neutral) are weak.
- **No DMARC** → zero enforcement. **DMARC `p=none`** → monitoring only, no enforcement.
- DKIM: probe selectors `default, google, selector1, selector2, mail, dkim` at `<selector>._domainkey.<domain>`.
- **DNSSEC not configured** → cache-poisoning risk.
- **Zone transfer allowed** → exposes the full DNS zone.

### Google / GitHub dorks (recon, 01-recon-osint, initial-access-recon)
```
site:target.com filetype:pdf                      # exposed documents
site:target.com inurl:admin                       # admin panels
site:target.com intitle:"index of"                # open directory listings
site:target.com ext:env OR ext:config             # config files
site:target.com ext:sql | ext:txt | ext:log
"@target.com" site:linkedin.com                   # employee enumeration
"target.com" site:pastebin.com                    # credential leaks
# GitHub
org:targetorg api_key
filename:.env target.com
filename:.env "DB_PASSWORD"
extension:pem private
extension:sql mysql dump password
"target.com" password / api_key / secret
```

### Shodan pivots (initial-access-recon, 01-recon-osint v3)
```bash
shodan search "hostname:domain.com"
shodan search "org:Company Name"
shodan search "ssl:domain.com"
```
Pivot on **favicon mmh3 hash** and **JARM/JA4S** server fingerprints to cluster sibling infra behind CDNs.

### Port scanning (recon, 01-recon-osint, initial-access-recon)
```bash
nmap -sn 203.0.113.0/24                                  # ping sweep / live hosts
nmap -sC -sV -oN scan-results.txt $ARGUMENTS             # default scripts + version
nmap -sV -sC --top-ports 1000 -oA scan_results <ip>
nmap -sV -sC -p- -T4 -oA full_scan <ip>                  # full TCP range
sudo nmap -sU --top-ports 1000 target.com                # UDP
nmap -sV --version-intensity 9 target.com                # aggressive version detection
sudo nmap -O target.com                                  # OS fingerprint
masscan -p1-65535 10.10.10.10 --rate=1000                # fastest
rustscan -a target.com -- -sC -sV                        # fast + nmap handoff
```
Use `-Pn` if the host appears down but is in-scope. **IDS/firewall evasion** (initial-access-recon): `nmap -sA target.com` (ACK firewall mapping), `nmap -T2 -f target.com` (slow + fragment), `nmap -D RND:10 target.com` (decoys).

### Subdomain takeover (01-recon-osint v3)
For every discovered subdomain with a dangling `CNAME` pointing to an **unclaimed S3 / Azure / GitHub Pages / Heroku / Fastly** target, flag as takeover candidate and identify the orphaned-service fingerprint (ref: can-i-take-over-xyz).

### Cloud bucket enumeration (initial-access-recon)
```bash
curl -I https://company.s3.amazonaws.com                       # AWS S3
aws s3 ls s3://bucketname --no-sign-request                    # listable bucket
curl -I https://company.blob.core.windows.net/container        # Azure Blob
curl -I https://storage.googleapis.com/company-bucket          # GCS
```
Permute org name: `company-backup, company-data, company-dev`, … Tools named in source: `s3scanner`, `GCPBucketBrute`, MicroBurst `Invoke-EnumerateAzureBlobs`.

### Technology fingerprinting signals (tech_fingerprint.py, 01-recon-osint)
Header tells: `Server:` (web server+version), `X-Powered-By:` (framework), `Set-Cookie` name (`PHPSESSID`=PHP, `JSESSIONID`=Java), `X-Generator` (CMS). Body signature regexes actually used:
- **WordPress:** `wp-content`, `wp-includes`, `wp-json`, `/xmlrpc\.php`
- **Drupal:** `Drupal\.settings`, `drupal\.js`, `/sites/default/`
- **Joomla:** `/media/jui/`, `com_content`, `/administrator/`
- **React/Next:** `react\.production\.min\.js`, `_reactRootContainer`, `__NEXT_DATA__`
- **Angular:** `ng-version`, `ng-app` — **ASP.NET:** `__VIEWSTATE`, `__EVENTVALIDATION` — **Laravel:** `laravel_session`, `csrf-token` — **Django:** `csrfmiddlewaretoken`
- **WAF:** Cloudflare `cf-ray`/`__cfduid`, AWS WAF `x-amzn-requestid`/`awswaf`, Akamai `x-akamai`, Sucuri `x-sucuri`, ModSecurity `mod_security`/`NOYB`
- **CDN by header:** `cf-ray`→Cloudflare, `x-amz-cf-id`→CloudFront, `x-fastly-request-id`→Fastly

**Security headers to score (missing = finding):** `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.

### JS secret extraction (initial-access-recon)
```bash
echo "https://target.com" | hakrawler | grep "\.js$" | sort -u
cat file.js | grep -Eo "(api|token|key|secret|password)[\"']?\s*[:=]\s*[\"'][^\"']{10,}[\"']"
```

### PCAP traffic analysis (08-network-security)
```bash
tshark -r capture.pcap -q -z io,phs                                  # protocol hierarchy
tshark -r capture.pcap -q -z conv,tcp                                # TCP conversations
tshark -r capture.pcap -q -z endpoints,ip                            # IP endpoints
tshark -r capture.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.uri
tshark -r capture.pcap -Y dns.flags.response==0 -T fields -e ip.src -e dns.qry.name
tshark -r capture.pcap --export-objects http,./extracted_files/
```
**Beaconing (regular SYN intervals to one dst):**
```bash
tshark -r capture.pcap -Y "ip.dst == 203.0.113.10 and tcp.flags.syn==1" \
  -T fields -e frame.time_epoch | \
  awk 'NR>1{printf "%.0f\n", ($1-prev)} {prev=$1}' | sort | uniq -c | sort -rn
# consistent counts at specific intervals = beaconing
```
**DNS tunneling:**
```bash
tshark -r capture.pcap -Y "dns.qry.name.len > 50" -T fields -e ip.src -e dns.qry.name | head -50
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | \
  awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20   # high-volume to one parent domain
```
**Scripted beacon scoring (pcap_analyzer.py):** jitter ratio = stddev(intervals)/mean; flag when `jitter < 0.3 and avg_interval > 1` (HIGH if `jitter < 0.1`). Port-scan heuristic: a src→dst flow touching `>20` unique dports = scan (`>100` = Horizontal). DNS suspicious flags: domain length `>50` chars (DGA/tunneling) or `>100` queries (beaconing).

### Suricata / Snort / Zeek detections (08-network-security)
Suricata rule grammar: `action protocol src_ip src_port -> dst_ip dst_port (options)`.
```suricata
# DNS Tunneling — long subdomain query
alert dns $HOME_NET any -> any any (
    msg:"POLICY Possible DNS Tunneling - Long Subdomain Query";
    dns.query; content:"."; byte_test:1,>,50,0,relative;
    threshold:type both, track by_src, count 20, seconds 60;
    classtype:policy-violation; sid:9000002; rev:1;)

# Data exfiltration — large HTTP POST
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"EXFILTRATION Possible Data Exfiltration - Large HTTP POST";
    flow:established,to_server; http.method; content:"POST";
    http.request_body; content:!""; dsize:>1000000;
    threshold:type both, track by_src, count 3, seconds 300;
    classtype:policy-violation; sid:9000004; rev:1;)

# Lateral movement — PsExec over SMB
alert smb $HOME_NET any -> $HOME_NET 445 (
    msg:"LATERAL-MOVEMENT PsExec Lateral Movement Detected";
    flow:established,to_server; content:"PSEXESVC"; nocase;
    classtype:trojan-activity; sid:9000003; rev:1;)

# Self-signed C2 cert
alert tls $EXTERNAL_NET any -> $HOME_NET any (
    msg:"MALWARE Suspicious TLS Certificate - Self-Signed C2";
    tls.cert_subject; content:"CN=localhost";
    tls.cert_issuer; content:"CN=localhost";
    classtype:trojan-activity; sid:9000005; rev:1;)
```
Snort 3 SQLi example: `content:"' OR '1'='1"; nocase;` with `http_uri; flow:established,to_server;`. Test offline: `suricata -r capture.pcap -S custom.rules -l ./logs/`.

### Firewall audit (08-network-security) — never-allow rules
**iptables checklist:** default policy `DROP` on all chains; INPUT = established/related + explicit allows only; FORWARD `DROP` unless router; SSH/22 restricted to admin source IPs; **no `0.0.0.0/0` → ALL ports**; logging on DROPs; anti-spoofing for RFC1918 on external ifaces; ICMP restricted; port 0 blocked.
**AWS Security Group — must NEVER exist in prod:**
```
✗ Inbound 0.0.0.0/0 → 22 (SSH open to internet)
✗ Inbound 0.0.0.0/0 → 3389 (RDP open to internet)
✗ Inbound 0.0.0.0/0 → 0-65535 (any port from internet)
✗ Outbound 0.0.0.0/0 → 0-65535 (unrestricted egress)
✓ Inbound 0.0.0.0/0 → 443 OK;  ✓ Inbound 10.0.0.0/8 → 22 OK
```
View rules: `iptables -L -n -v --line-numbers`. Fix pattern for exposed SSH: replace `-A INPUT -p tcp --dport 22 -j ACCEPT` with `... --dport 22 -s [admin_ip] -j ACCEPT`.

---

## Tools & commands (only those named in source)

- **DNS / subdomain:** `dig`, `host`, `whois`, `fierce`, `dnsrecon -d <d> -t brt`, `amass enum -passive|-active -d <d> -brute`, `subfinder -d <d> -silent`, `assetfinder --subs-only`, `sublist3r -d <d>`, `gobuster dns -d <d> -w <wl>`, `ffuf -u http://FUZZ.<d> -mc 200,301,302`. Bundled scripts: `subdomain_enum.py` (`--passive-only`, `-w`, `-t`, `-n`), `dns_recon.py` (`--check-zone-transfer`).
- **Port/host scan:** `nmap` (`-sC -sV -sU -sn -sA -O -p- -Pn -T2/-T4 -f -D RND:10 --top-ports --version-intensity -oA/-oN`), `masscan --rate`, `rustscan -a <t> -- <nmap-args>`, `arp-scan -l`, `netdiscover -r`, `fping -a -g`, `traceroute -T/-I`, `mtr`.
- **Web recon:** `whatweb`, `gobuster dir|vhost`, `feroxbuster`, `ffuf`, `dirsearch`, `arjun`, `ParamSpider`, `hakrawler`, `LinkFinder`, `nikto -h`, `nuclei -u <t> -t <templates>`, bundled `tech_fingerprint.py` (`-u/-U`).
- **OSINT / harvest:** `theHarvester -d <d> -b all`, `exiftool`, `trufflehog`, `gitleaks detect --source`, `recon-ng`, SpiderFoot, `linkedin2username`, `sherlock`. Sources: crt.sh, SecurityTrails, DNSDumpster, ipinfo.io, bgp.he.net, Shodan, Censys, HaveIBeenPwned, dehashed.
- **Cloud:** `s3scanner`, `GCPBucketBrute`, MicroBurst `Invoke-EnumerateAzureBlobs`, `aws s3 ls --no-sign-request`.
- **Network/traffic:** `tshark`/Wireshark, `tcpdump`, `suricata -r <pcap> -S <rules> -l`, `snort 3`, `zeek`, NetworkMiner, bundled `pcap_analyzer.py` (`--dns`, `--top-talkers`, `--detect-beaconing`). Python libs: `scapy`, `dpkt`, `dnspython`, `python-whois`, `shodan`.

---

## Expert gotchas / bypasses

- **Wildcard DNS poisons brute-force.** Always run wildcard detection first (resolve `randomnonexistent12345.<domain>`); if it answers, every brute-forced name "resolves." Filter against the wildcard IP before reporting (subdomain_enum.py).
- **Confirmed vs candidate, always.** CT-log names are *candidates* until resolved + HTTP-probed. Never report a crt.sh-only hostname as live infrastructure — tag discovery source per asset (01-recon-osint precision rule).
- **crt.sh URL encoding matters:** `%25.` in a shell `curl` (the `%` is escaped for the URL) vs `%.` inside Python where you control encoding directly. Mixing them returns empty results.
- **Encrypted-traffic era (08-network-security v3):** TCP-centric Suricata rules silently miss **QUIC / HTTP3 (UDP/443)** and **encrypted DNS (DoH/DoT/DoQ)**. Fingerprint with **JA4/JA4S/JA4H/JA4X** (successor to JA3) instead of trying to decrypt; baseline resolvers and flag rogue DoH endpoints. Prefer a Zeek-first pipeline (`conn`, `ssl`, `http`, `dns`, `x509`, JA4 logs) and write detections against Zeek notices.
- **Beaconing has jitter.** Naive "exact interval" detection misses jittered C2. Use jitter-aware scoring (`stddev/mean`, RITA-style), byte-count regularity, and long-connection scoring — not just timestamp deltas.
- **AXFR is low-effort, high-payoff but often refused** — try *every* NS, not just NS1; a single misconfigured secondary leaks the whole zone.
- **SMTP `VRFY` and SMTP-callback email verification are detectable** — they touch the target's mail server and can trip alerts. Prefer passive email-format inference (LinkedIn + known pattern) before active verification (initial-access-recon).
- **`tech_fingerprint.py` sets `session.verify = False`** to fingerprint hosts with broken/self-signed TLS — fine for recon, but it means an SSL error is itself a finding, not a dead end. Don't conflate "cert invalid" with "host down."
- **`http_uri` vs `http.uri`, `content` ordering with `distance:`/`relative`** — Snort 2 and Snort 3 syntax differ; Suricata `byte_test:1,>,50,0,relative` measures from the last content match. Test rules offline against a known-bad PCAP before deploying or they silently no-op.
- **Don't distribute breach data.** HaveIBeenPwned/combolist correlation is *check-only* to prioritize accounts; never exfiltrate or redistribute breach contents (osint-recon, 01-recon-osint).
- **Source maps & CI logs leak internal paths** — extend dorking to `*.map` files, GitHub Actions logs, and npm/PyPI package metadata (01-recon-osint v3).
- **Stay in scope, rate-limit, log every command.** Never scan adjacent/out-of-scope systems; if you find evidence of a third-party compromise, alert the user immediately and pause (recon boundaries).

---

## Delegate to

- **`recon`** — use when you need the structured active/passive target-mapping pass and a clean recon report template (DNS, ports, fingerprinting, attack-surface summary).
- **`osint-recon`** — use for the deeper open-source investigative side: people, organizations, leaked data, document metadata, multi-source correlation with confidence ratings.
- **`01-recon-osint`** — use for automated/at-scale enumeration via its bundled `subdomain_enum.py` / `dns_recon.py` / `tech_fingerprint.py`, takeover detection, and JA4/favicon pivots.
- **`initial-access-recon`** — use for the full offensive initial-access toolbelt: active subdomain brute-force, cloud-bucket hunting, JS secret mining, email/phishing recon, and IDS-evasion scan flags.
- **`08-network-security`** — use whenever a PCAP, an IDS/IPS signature request, or a firewall/zoning audit is in play; carries the Suricata/Snort/Zeek templates and the beaconing/tunneling/exfil hunt logic.

## Hand-off (next clusters)
- Live web apps → **web-pentest / owasp-audit / api-audit**.
- Cloud assets & buckets → **cloud-audit / container-audit**.
- Discovered services/versions → **dependency-audit / vuln scanner**.
- Suspicious infra or IOCs → **threat-hunting / siem-detection**.
- Evidence of active compromise → **incident-triage**.
