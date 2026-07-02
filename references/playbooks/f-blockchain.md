# Blockchain & Smart-Contract Security Playbook

Authorized audit / bug-bounty methodology for on-chain programs, off-chain Rust services, and multi-chain VMs. Distilled from `solana-rust-deep-audit`, the per-chain vulnerability scanners (Solana/Algorand/Cairo/Cosmos/Substrate/TON), `web3-blockchain`, `entry-point-analyzer`, `dimensional-analysis`, and `token-integration-analyzer`. Remediation framing is preserved: every finding states attacker, action, and impact (funds stolen / funds locked / state corrupted / access bypassed), then a fix.

---

## When this applies

Route an engagement here when the target shows any of:
- **Solana / Anchor**: `Anchor.toml`, `programs/*/src/lib.rs`, `Cargo.toml` with `anchor-lang` or `solana-program`, `invoke`/`invoke_signed`, `Signer<'info>`, `#[account(...)]`, seeds/bump.
- **EVM / Solidity / Vyper**: `.sol`/`.vy`, Hardhat/Foundry, DeFi (DEX, lending, vault, bridge, staking), MEV/oracle exposure.
- **Cosmos SDK / CosmWasm**: Go `x/` modules, `go.mod` with `cosmos-sdk`, `cosmwasm_std`, IBC, `msg_server.go`, BeginBlock/EndBlock.
- **Cairo / StarkNet**: `.cairo`, `Scarb.toml`, `#[l1_handler]`, `felt252`, L1↔L2 bridges.
- **Substrate / Polkadot**: `.rs` with `#[pallet]`, `frame_support`, dispatchables, weights, parachains.
- **TON**: `.fc`/`.func`/`.tact`, FunC, Jettons, `recv_internal`, `transfer_notification`.
- **Algorand**: `.teal`/PyTeal, smart signatures, group transactions, rekeying.
- Any request to "audit a contract / protocol", "find DeFi bugs", "review CPI/PDA", "check overflow", "smart contract security review".

If the stack is plain EVM Solidity with no Cosmos context, prefer Solidity tooling (Slither/Mythril/Foundry), not the Cosmos scanner (cosmos-vulnerability-scanner explicit non-use).

---

## Methodology

Map before you hunt. Validate before you report. Only report what you can exploit.

1. **Recon / structural overview** — detect languages and layout (`solana-rust-deep-audit` Phase 1):
   - `find . -name "Anchor.toml" -o -name "Cargo.toml"`; count `.rs` (excl. `target/`), `.ts`/`.js` (excl. `node_modules/`), `package.json`, `go.mod`, `Scarb.toml`, `.teal`, `.fc`.
   - Identify on-chain programs, off-chain Rust (services/SDKs/indexers/bots), TS/JS clients, config (`.env`, deploy scripts).
2. **Entry-point map** — run `entry-point-analyzer` on every program dir. Enumerate **state-changing** entry points only (exclude `view`/`pure`/`@view`/non-`mut` Solana/`get` FunC/CosmWasm `query`). Classify by access: Public (unrestricted), Role-restricted (admin/owner/governance/guardian/minter/keeper/relayer), Restricted-review-required (dynamic trust lists), Contract-only (callbacks, hooks). Always include callbacks — they define trust boundaries.
3. **Dependency + secret snapshot** — `cargo audit`, `npm audit`; check `go.mod`/SDK version (Cosmos breaks across v0.47/v0.50/v0.53); grep committed secrets and `git log --all --full-history -- "*.env"`.
4. **Write architecture.md + coverage.md** — architecture.md: program list + instruction counts, privilege hierarchy (who calls what), vaults/PDAs/upgrade authorities, external deps (oracles, SPL/bridged assets), trust boundaries (untrusted inputs). coverage.md: the entry-point × vuln-class matrix from the **Coverage protocol** below — one row per state-changing entry point, one column per applicable vuln class. Feed both into every hunt agent/pass. Every subsequent step fills cells; nothing concludes with a blank cell.
5. **Parallel hunt** — split by class: (A) account-model/access-control, (B) DeFi economics, (C) Rust memory/safety off-chain, (D) crypto/timing, (E) supply-chain/secrets, (F) off-chain services + TS clients. For Cosmos spawn core/state/advanced scanners plus conditional IBC/EVM/CosmWasm.
6. **Dimensional pass** — on any arithmetic-heavy DeFi/financial code, run `dimensional-analysis` to annotate units/decimals (`D18{tok}`, `D27{UoA/tok}`) and surface unit/scale mismatches. Annotate every ratio gate with its expected scale (e.g. `1.5` meaning 1.5× vs `1_500_000` meaning 1.5× in e6 fixed-point) — a mismatch of e6 vs raw causes fund drain or lock.
7. **Token-integration pass** — if the protocol touches external tokens, run `token-integration-analyzer` against the weird-ERC20 database (missing return value, fee-on-transfer, rebasing, blocklist, reentrant hooks, low/high decimals).
8. **Deep structural** — `trailmark-structural` on the top 2–3 programs by entry-point count/complexity; `variant-analysis` on every confirmed finding (if root cause X is in one instruction, sweep all others).
9. **Validate / kill false positives** — `fp-check` methodology. For each candidate: can you build a concrete attack tx? Does the guard actually exist across the FULL call chain (Anchor constraints, upstream validators)? Is impact one of the four real classes? Be precise about which framework auto-checks what.
10. **Fuzz** — for every CRITICAL/HIGH on a parsing/arithmetic path, write a `cargo-fuzz` harness (60s+, ASan) and a `proptest` property test for integer math (`harness-writing` patterns).
11. **PoC** — write runnable PoC against `solana-test-validator` / mainnet-fork / sandbox — **never mainnet**. Include a `--check-only` detector and the fix alongside.
12. **Report** — severity-graded findings; each card = description, attack scenario (numbered), vulnerable code (path:line), PoC pointer, recommended fix, references. Add a "what was done well" section to build trust.

---

## Coverage protocol — the anti-skip mechanism

A checklist gets skimmed. A ledger with a completion gate does not. **Do not conclude the
audit until every cell of the coverage matrix is explicitly dispositioned.** "I didn't see
anything" is not a disposition; "traced X, guard at line N holds because Y" is.

### 1. Build the coverage matrix (before hunting)

Rows = every state-changing entry point from Step 2. Columns = every vuln class that applies
to this stack (pull the column set from the High-signal checklist section below — Solana gets
the Solana columns, EVM gets the DeFi + EVM columns, etc.). Write it to `coverage.md`:

```
| Entry point            | AccessControl | Arithmetic | Oracle | Reentrancy | CPI/ExtCall | TokenIntegration | DoS/Halt | Replay | ... |
|------------------------|---------------|------------|--------|------------|-------------|------------------|----------|--------|-----|
| deposit()              |               |            |        |            |             |                  |          |        |     |
| withdraw()             |               |            |        |            |             |                  |          |        |     |
| admin_set_oracle()     |               |            |        |            |             |                  |          |        |     |
| liquidate()            |               |            |        |            |             |                  |          |        |     |
```

Every entry point is a row. **Missing a row = a missed attack surface.** Re-derive the row list
from `entry-point-analyzer` output, not from memory — callbacks, hooks, and admin instructions
are the ones humans forget.

### 2. Disposition every cell

Each cell gets exactly one mark:
- **`✓clean`** — traced the full path, the guard exists and holds. Record *why* (which
  constraint/check, at which line) in a footnote. A bare ✓ with no reason is not allowed.
- **`⚠finding`** — candidate found; link to its finding ID. Goes to the validation gate.
- **`n/a`** — class cannot apply here; state the one-line reason (e.g. "no external call",
  "no arithmetic", "read-only inputs"). `n/a` without a reason is treated as unfilled.
- **`—blocked`** — could not analyze (no source, obfuscated, out of scope). Name the blocker.
  Blocked cells are reported as coverage gaps, never silently dropped.

### 3. Completion gate (definition of done)

The audit is **not done** while any cell is blank. Before writing the report, assert:
- Every entry point from Step 2 has a row.
- Every cell is `✓clean` / `⚠finding` / `n/a` / `—blocked` — zero blanks.
- Every `⚠finding` passed the Step 9 validation gate (concrete tx or traced source→sink) or was
  downgraded to `✓clean`/FP with reason.
- Every `✓clean` has its justification footnote.
- `variant-analysis` ran on each confirmed root cause, and the sibling cells it touches were
  re-marked (a bug in `deposit` arithmetic means re-checking the Arithmetic column for *every*
  row, not just deposit).
- Cross-cutting classes that don't fit the per-entry grid have their own checklist and are all
  ticked: upgrade authority / proxy admin, initialization & re-init, global invariants
  (total_supply == Σ balances, vault solvency), pause/emergency paths, and the off-chain +
  dependency + secrets sweep (Steps 3, 7-class E/F).

Only when the matrix is fully dispositioned and the cross-cutting list is ticked do you write
the report. State the coverage numbers in it: "N entry points × M classes = K cells; C clean,
F findings, X n/a, B blocked" — so the reader sees exactly what was and wasn't examined.
Silence is not coverage. An honest `—blocked` beats a false `✓clean` every time.

---

## High-signal checklist

Crown-jewel patterns, defanged. Each line: pattern → severity cue.

### Solana / Anchor (`solana-rust-deep-audit`, `solana-vulnerability-scanner`)
- **Arbitrary CPI** — `invoke()`/`invoke_signed()` with user-supplied program ID; program key checked *after* invoke (wrong order). `rg "invoke\(|invoke_signed\(" programs/ -A5`. CRITICAL. Fix: `require_keys_eq!(token_program.key, &spl_token::ID)` or Anchor `Program<'info, Token>`.
- **Non-canonical PDA bump** — `create_program_address` with a user-supplied bump instead of `find_program_address`. Every `create_program_address` hit needs manual review. CRITICAL. Store the canonical bump and reuse it in `invoke_signed`.
- **PDA seed collision** — seeds don't uniquely identify the account (e.g. swappable `user_id`/`amount`); add a type-discriminator prefix (`b"user-vault"`).
- **Anchor seeds bump not stored** — `#[account(seeds=[..], bump)]` recalculated per call vs `bump = vault.bump`. Review each.
- **Missing owner check (native)** — `try_from_slice` / `try_deserialize` without `account.owner == program_id`. HIGH. Anchor `Account<'info, T>` auto-validates owner + discriminator; native does not.
- **Missing signer check** — authority op without `is_signer` / `Signer<'info>`. CRITICAL.
- **init_if_needed re-init** — already-initialized account re-triggers init logic; every `rg "init_if_needed"` hit is a candidate.
- **Discriminator / type confusion** — `AccountLoader` / unsafe load without discriminator check; accounts sharing seed prefixes substitutable across roles.
- **Sysvar spoof / introspection** — `load_instruction_at` (unchecked, pre-1.8.1) vs `load_instruction_at_checked`; absolute instruction index allows reuse — prefer relative `load_current_index_checked`. MEDIUM–HIGH.
- **`#[account(mut)]` over-permission** — writable account where read-only expected; `close` without confirming no post-close read.
- **CPI privilege escalation** — `invoke_signed` over sensitive authority seeds into a non-trusted callee that can re-invoke back with the program's signature.

### DeFi economics (cross-chain)
- **Oracle manipulation** — TWAP window < ~5 min, single-source price, no staleness check (`clock.unix_timestamp`), flash-borrowable price impact. `rg "price|oracle|pyth|switchboard|twap" -i`. CRITICAL with a profit path.
- **Flash-loan / atomic composability** — value set and read in the same slot/tx without guards; deposit→trigger→withdraw atomically.
- **Precision loss / rounding** — division before multiplication truncates in attacker's favor (`(amount/1000)*rate` vs `amount*rate/1000`); inconsistent floor/ceil drains dust over many txns.
- **Inflation / empty-vault attack** — first depositor donates directly to vault, manipulates share price, later depositors round to zero shares (ERC4626-style). Fix: virtual shares or minimum initial deposit. `rg "total_supply|total_shares|exchange_rate" -i`.
- **Fee griefing / dust** — rounding always in attacker's favor; many tiny accounts that cost the protocol lamports/gas.
- **Reentrancy (EVM)** — external call before state update; Checks-Effects-Interactions / ReentrancyGuard. (web3-blockchain)
- **Delegatecall injection (EVM)** — `delegatecall` to user-controlled target → storage/owner takeover. Whitelist targets.
- **MEV / front-running** — mempool-visible price-sensitive swaps; commit-reveal, slippage bounds, private mempool.
- **DoS by unbounded loop (EVM)** — push-payment loops; revert-in-fallback griefer becomes top bidder. Use pull-over-push.

### Cosmos SDK / CosmWasm (`cosmos-vulnerability-scanner`)
- **Non-determinism = chain halt** (highest class) — `range` over Go maps, `int`/`uint`/`float`, goroutines/`select`, `rand`, `time.Now()`, memory addresses, `sort.Sort` (unstable), `filepath.Ext`. Use sorted keys, `int64`/`math.Int`/`math.LegacyDec`, `ctx.BlockTime()`. Only flag on consensus path.
- **Slow / panicking ABCI** — unbounded loops in BeginBlock/EndBlock/PreBlock (iterate all users/pools); `Must*` constructors, `Quo`/`Div` by zero, slice `[0]` on empty. Batch with per-block limits.
- **Signer mismatch** — `cosmos.msg.v1.signer` proto annotation ≠ field used for authz in `msg_server.go` (multi-address-field handlers). CRITICAL fund loss.
- **Missing msg_server validation** — `ValidateBasic` deprecated/facultative since v0.53; if removed without handler-level checks, invalid msgs reach state. Validate authority, params, numeric sign in the handler.
- **Ignored keeper errors** — unchecked `bankKeeper.SendCoins` lets withdrawals "succeed" then decrement balance. Enable `errcheck`.
- **AnteHandler bypass** — nested `MsgExec`(authz)/group-proposal messages skip outer-only checks; recurse into inner msgs. `x/authz`/`x/feegrant`/vesting grants must respect `BlockedAddr` (GHSA-4j93-fm92-rp4m). Manual msg routing bypasses ante entirely.
- **IBC** — token inflation, non-deterministic acks, any chain can open a channel ("counterparty trusted" is a rejected rationalization).
- **Rejected rationalizations**: "ValidateBasic catches this", "behind governance so safe", "IBC counterparty trusted", "rounding is only a few tokens", "EVM precompile handles rollback".

### Cairo / StarkNet (`cairo-vulnerability-scanner`)
- **Unchecked `#[l1_handler]` `from_address`** — any L1 contract messages in → infinite mint. CRITICAL. Assert `from_address == stored_l1_bridge`.
- **felt252 arithmetic overflow** — felt252 used for balances/amounts without bounds; prefer u128/u256.
- **Storage collision** — conflicting storage-var hashes.
- **Signature replay** — no nonce tracking / nonce not incremented; domain separator missing chain ID + contract address (cross-chain replay).
- **L1↔L2 messaging** — L1 must validate address < STARKNET_FIELD_PRIME and implement message cancellation; symmetric L1/L2 access; locked funds on unhandled failure.
- **Missing caller validation** — no `get_caller_address()` on sensitive functions.

### Substrate / FRAME (`substrate-vulnerability-scanner`)
- **Arithmetic overflow** — bare `+ - * /` wrap in release; require `checked_*` / `saturating_*`, `try_into()` on casts. CRITICAL.
- **Don't panic (DoS)** — `unwrap()`/`expect()`/unchecked indexing in dispatchables crash the node. Validate with `ensure!`; check zero divisor.
- **Weights & fees** — fixed weight on variable-cost op → spam DoS; bound all inputs; use benchmarking framework.
- **Bad origin** — `ensure_signed` on privileged ops; require `ensure_root`/ForceOrigin/AdminOrigin; remove sudo pre-prod. CRITICAL.
- **Verify-first-write-last** — pre-v0.9.25 storage writes persist on error; upgrade or `#[transactional]`.
- **Unsigned tx validation** — replay/spam; prefer signed; authenticate source.
- **Bad randomness** — `RandomnessCollectiveFlip` is collusion-prone; use BABE `RandomnessFromOneEpochAgo`, `random(subject)` not `random_seed()`.

### TON / FunC (`ton-vulnerability-scanner`)
- **Fake Jetton / missing sender check** — `transfer_notification` handler that credits without validating sender == stored jetton wallet address → unauthorized crediting. CRITICAL. `throw_unless(err, equal_slices(sender, jetton_wallet_address))`.
- **Integer-as-boolean** — FunC true is `-1`, not `1`; positive ints used as bool break `~`/`&`/`|` logic.
- **Forward TON without gas check** — unbounded `forward_ton_amount` drains balance; require `msg_value >= tx_fee + forward_amount`.

### Algorand / TEAL (`algorand-vulnerability-scanner`)
- **Rekeying** — unchecked `RekeyTo` → attacker rekeys account authorization. CRITICAL. Assert `Txn.rekey_to() == Global.zero_address()`.
- **CloseRemainderTo / AssetCloseTo** — unchecked close fields drain remaining balance.
- **Group transaction manipulation** — missing `Global.group_size()`/index checks; assuming tx order; use Lease for replay protection.
- **Inner-tx fee** — set explicitly to 0; validate all inner-tx fields; RekeyTo not user-controlled (Teal v6+).
- **Access control** — Update/Delete unprotected; OnComplete unvalidated on ApplicationCall.

### Rust off-chain (`rust-safety-checklist`)
- **`unsafe` without documented invariant** — transmute without size/align proof, pointer arith from external data, unsafe `Send`/`Sync`. Audit each.
- **Integer overflow/underflow** — release-mode wrapping in balance/fee/reward/slippage math; `checked_*`/`saturating_*`; even u128 overflows mid-calc.
- **Data races / TOCTOU** — lock released between check and use; double-lock deadlock; non-Send across tasks.
- **Missing zeroization** — keys/seeds/passwords not zeroed; use `Zeroizing<T>` / `zeroize`.
- **`unwrap()`/`expect()` on user paths** — panic crashes bot/indexer/validator.
- **Insecure / fail-open defaults** — `env::var(..).unwrap_or("default_secret")`, devnet RPC fallback in a mainnet bot, hardcoded keys/base58 secrets.
- **Logging secrets** — keypair/secret/auth token in `log::*`/`tracing::*`; redact.

### Off-chain services & TS clients
- RPC input validation (tx/account deserialization without bounds), client-side-only access control bypassable via direct RPC, dependency confusion / typosquatting, SSRF/injection in indexers, TOCTOU between bot simulation and submission, private keys loaded from file/env/hardcoded in JS.

### Token integration (`token-integration-analyzer`)
- Weird-ERC20 patterns: missing return value (USDT/BNB/OMG), fee-on-transfer (STA/PAXG) → credit `balanceAfter - balanceBefore` not `amount`, rebasing/balance-mod-outside-transfer (Ampleforth/Compound), upgradable (USDC/USDT), flash-mintable (DAI), blocklists, pausable, approval race, revert-on-zero, low decimals (USDC 6, Gemini 2), high decimals (YAM-V2 24), reentrant ERC777 hooks, code-injection via token name. Owner privileges: uncapped mint, no-timelock upgrade, pause-traps-funds. Rejected rationalization: "ERC20 checks pass so it's standard" — 20+ weird patterns live beyond conformity.

---

## Tools & commands

Only tools named in the sources.

- **Solana/Rust**: `cargo audit`, `cargo geiger`, `cargo-fuzz` (+ AddressSanitizer), `proptest`, Trident (Solana-native fuzzer), Trail of Bits `solana-lints`, `anchor test`, `solana-test-validator`, `solana program show <ID>` (upgrade authority).
- **EVM (web3-blockchain)**: Slither (`slither . --detect reentrancy-eth,tx-origin`, `--print entry-points`, `--print human-summary`), Mythril (`myth analyze`), Manticore, Echidna (fuzzer), Foundry (`forge test --fork-url ...`), Hardhat (mainnet fork), Tenderly.
- **Token**: `slither-check-erc`, `slither-prop`, `slither --print contract-summary`.
- **Algorand**: Tealer (`tealer contract.teal --detect all`, `--fail-on critical,high`).
- **Cairo**: Caracal (`caracal detect src/`, detectors `unchecked-l1-handler-from`, `unchecked-felt252-arithmetic`, `missing-nonce-validation`), Starknet Foundry, `cairo-test`.
- **Substrate**: `cargo-fuzz`, `test-fuzz`, benchmarking (`cargo build --release --features runtime-benchmarks` → `benchmark pallet`), `try-runtime`.
- **Cosmos**: Grep/Glob (not bash grep), `errcheck`/`goerr113` linters, race detector, `cosmos-sdk-codeql`.
- **TON**: TON Blueprint, `@ton/sandbox`, toncli, ton-compiler (largely manual review).
- **Generic grep starters**: `rg "invoke\(|invoke_signed\("`, `rg "create_program_address"`, `rg "init_if_needed"`, `rg "ensure_signed" pallets/ | grep -E "pause|admin|force"`, `rg "range.*map\[" / "time\.Now\(\)" / "float64"` (Cosmos), `rg "transfer_notification"` (TON), `rg "rekey_to"` (Algorand).

---

## Offensive layer — think like the drainer

Blackhat depth, whitehat rules (see persona §3c). Authorized targets only — your own
protocols, code you're hired to audit, or deliberately-vulnerable practice targets. Inside that
scope, stop auditing and start *robbing*. A vuln class is only interesting if you can turn it
into a transaction that takes value; this section is how you close that gap.

### 1. Attack economics — does the exploit pay?

A DeFi bug is not real until the attacker's PnL is positive. For every candidate on the money
path, compute the net take of the *cheapest* attacking transaction, assuming the attacker has
flash-loaned capital and one atomic tx:

```
profit = value_extracted
       − flash_loan_fee        (Aave ~0.05%, Balancer/Univ3 flash 0%, dYdX ~2 wei)
       − swap_slippage + price_impact   (size the trade against real pool depth / liquidity)
       − gas (L1: attack complexity × gas price; L2/Solana: near-zero, changes the calculus)
       − any protocol fee on the drained path
```

- **If profit > 0 for *any* borrowable size → CRITICAL/HIGH**, and severity scales with `profit × repeatability` (once vs every-block vs until-vault-empty).
- **If profit ≤ 0 at every size → downgrade.** A "manipulable" oracle whose correction costs more than it yields is not an exploit. Say so; don't inflate it.
- **Atomicity is a weapon.** Set-and-read-in-same-slot, deposit→manipulate→withdraw, borrow→attack→repay all collapse the "you'd need capital / you'd get front-run" objection. Model *with* atomicity by default.
- **L2/Solana gas is ~free** → dust-rounding and many-small-account griefing that are uneconomic on L1 mainnet become profitable. Recompute per chain.

### 2. Real-exploit hunting lens — the incident is the template

Every class below has a real on-chain drain behind it. Hunt by pattern-matching the *shape* of
past incidents onto this code, then prove the rematch. Study the Foundry reproductions in
DeFiHackLabs / DeFiVulnLabs — clone, run the PoC, internalize the root cause, then ask "does
this protocol have that shape?"

| Incident shape | Root cause to hunt | Your rematch question |
|---|---|---|
| **Flash-loan + spot-oracle** (many: bZx, Cheese, Warp) | price read from a manipulable spot pool inside a value-moving call | Can I move the price source atomically and settle at the manipulated price? |
| **Inflation / first-depositor** (ERC4626-era) | share price = assets/supply with a donation vector + round-to-zero | Can value reach the vault *outside* deposit accounting? Do late deposits round to 0 shares? |
| **Read-only reentrancy** (many post-2022) | view function returns stale state mid-external-call; consumer trusts it | Does any integrator read a price/share value that's inconsistent during a callback? |
| **Precision / rounding drain** | div-before-mul, floor always favoring caller | Can I loop the rounding error to accumulate dust into real value? |
| **Missing signer / owner** (Solana), **bad origin** (Substrate), **fake-jetton** (TON) | authority op reachable without the authority | Can I reach the privileged effect with an account I control? |
| **Governance / upgrade seizure** (many) | timelockless upgrade key, or proposal that reaches a privileged sink | Can I (or a compromised key) swap logic or drain via an "admin" path? |
| **Bridge / L1↔L2 message forgery** (Cairo `l1_handler`, Wormhole-class) | message consumed without validating `from_address`/guardian set | Can I forge or replay a cross-domain message into a mint/unlock? |
| **Signature replay** | missing nonce / domain separator without chainId+contract | Can I replay a signed action cross-tx or cross-chain? |

Rejected excuses that hide real drains: "you'd need too much capital" (flash loan), "you'd get
front-run" (private mempool / atomic), "it's only dust" (loop it / free gas on L2), "governance
controls it" (governance is an attack surface), "the oracle is Chainlink so it's fine" (check
staleness + the *consumer's* freshness assumption, not just the feed).

### 3. Weaponize into a runnable PoC

The finding is done when there's a transaction that takes the value against a **fork /
test-validator / sandbox — never mainnet**. Skeletons:

- **EVM flash-loan / oracle** — Foundry: `vm.createSelectFork($RPC, BLOCK)`; borrow (Aave
  `flashLoanSimple` / Uniswap V2 `swap` callback / Balancer `flashLoan`); in the callback move
  the price source, interact with the target at the manipulated price, repay, and
  `emit log_named_decimal_uint("profit", token.balanceOf(address(this)), decimals)`. Assert
  profit > 0. Use `vm.mockCall` to simulate a stale/manipulated feed when you don't control the pool.
- **Solana** — `solana-test-validator` + `anchor test` / `BanksClient`: build the exact
  instruction with the attacker-controlled account (spoofed owner, non-canonical bump, missing
  signer), submit, assert the balance/authority moved. `solana program show <ID>` first to note
  the upgrade authority as its own attack surface.
- **Invariant/fuzz the theft** — encode the economic invariant the exploit breaks
  (`vault_assets >= Σ user_claims`, `share_price monotonic`, `total_supply == Σ balances`) as an
  Echidna/Medusa/Foundry-invariant or a Trident (Solana) property, and let the fuzzer *find* the
  transaction sequence that violates it. This is how you catch the exploit you didn't think of.
- Ship a `--check-only` detector and the fix in the same PoC file. Offense pairs with remediation.

### 4. Attacker profitability + detection card (attach to every money-path CRITICAL/HIGH)

```
Attack:        <one line: what tx, what it takes>
Precondition:  <capital (flash-loanable? y/n), privilege, chain state, timing>
Net profit:    <extracted − fees − gas − slippage; show the arithmetic>
Repeatability: <once | per-block | until vault empty>
PoC:           <path to runnable fork/validator PoC>
Detection:     <the on-chain signal a monitor/searcher would see: anomalous ratio, oracle
                deviation, share-price jump, large atomic borrow→repay in one tx>
Fix:           <the change + the invariant it restores>
```

---

## Expert gotchas / bypasses

- **Anchor auto-checks are not gaps.** `Account<'info, T>` already validates owner + discriminator; `Signer<'info>` checks `is_signer`; `Program<'info, T>` validates program ID. Don't report these as missing on Anchor — only on native programs. Be precise about which layer handles what.
- **Constraint bypass via raw AccountInfo.** Anchor `has_one`/`constraint` run at the constraint layer; if the handler passes raw `AccountInfo` to sub-functions, those have no protection. Trace the full call chain.
- **Order matters in CPI.** A program-ID check *after* `invoke` is useless — the malicious CPI already executed.
- **Cosmos consensus-path gate.** A map iteration in a CLI command, or a panic in a query handler, is NOT a chain-halt finding. Verify reachability from BeginBlock/EndBlock/FinalizeBlock/msg_server/AnteHandler before flagging. Cross-module interactions (IBC reentrancy, EVM/Cosmos desync, authz escalation) hide the worst bugs.
- **Cosmos version drift.** Check `go.mod` first — v0.47 removed `GetSigners`, v0.50 added ABCI 2.0 + PreBlocker, v0.53 deprecated `ValidateBasic`. Patterns differ by version.
- **Nested-message ante bypass.** Outer-message-only ante checks miss messages wrapped in `MsgExec`/group proposals — always recurse.
- **felt252 looks like a number, behaves like a field element.** Overflow semantics differ from u256; never use it for balances.
- **TON booleans.** `1` as "true" silently breaks bitwise logic; true is `-1`.
- **Dimensional traps.** Lamports vs tokens vs shares, e6 vs e9 vs e18 scaling. A formula can be arithmetically correct and dimensionally wrong — e.g. a ratio gate expecting `1.5` (raw) but receiving `1_500_000` (e6-fixed-point) passes when it should block, or blocks when it should pass. Run `dimensional-analysis` on every financial calculation and annotate units before clearing a math finding as safe.
- **Validation discipline > volume.** 3 well-proven MEDIUMs beat 15 padded LOWs. Don't report theoretical oracle manipulation without a concrete profit path and price-impact estimate. Don't flag every `unwrap()`/`checked_add` — understand domain bounds and whether the path is user-controlled.
- **Inflation attack needs the donation vector.** It only works if value can reach the vault outside the deposit accounting (direct transfer). Confirm that path exists.
- **Reject "reputable team / uses OpenZeppelin" for tokens.** Library use doesn't protect against weird *external* tokens; verify defensive wrappers around every external call.

---

## Delegate to

Invoke via the Skill tool for a full-depth pass:

- **`solana-rust-deep-audit`** — use when the target is a Solana/Anchor program, off-chain Rust service/SDK, or TS client and you need the full 7-phase audit with PoCs and a graded report. The deepest skill in this cluster.
- **`solana-vulnerability-scanner`** — use for a fast focused Solana sweep of the 6 core account-model patterns (CPI/PDA/signer/owner/sysvar/introspection) when a full audit is overkill.
- **`cosmos-vulnerability-scanner`** — use for Cosmos SDK `x/` modules, CosmWasm, or IBC; spawns core/state/advanced + conditional EVM/IBC/CosmWasm scanners. Skip for plain Solidity.
- **`cairo-vulnerability-scanner`** — use for StarkNet/Cairo contracts and L1↔L2 bridges.
- **`substrate-vulnerability-scanner`** — use for FRAME pallets / Substrate runtimes (overflow, panic-DoS, weights, origin).
- **`ton-vulnerability-scanner`** — use for FunC/Tact contracts and Jetton handlers.
- **`algorand-vulnerability-scanner`** — use for TEAL/PyTeal (rekeying, group txns, close fields).
- **`web3-blockchain`** — use for EVM/Solidity/DeFi exploitation methodology (reentrancy, delegatecall, flash-loan, MEV) and Slither/Mythril/Foundry workflows.
- **`entry-point-analyzer`** — use first on any contract codebase to map state-changing entry points and access levels (Solidity/Vyper/Solana/Move/TON/CosmWasm).
- **`dimensional-analysis`** — use on arithmetic-heavy DeFi/financial code to annotate units/decimals and catch unit/scale mismatch bugs.
- **`token-integration-analyzer`** — use when a protocol implements or integrates external tokens; checks ERC20/721 conformity + 20+ weird-token patterns + owner-privilege risk.

Supporting (non-cluster but referenced): `fp-check` (kill false positives), `variant-analysis` (sweep a root cause), `trailmark-structural` (complexity/taint/blast-radius), `harness-writing` (fuzz harnesses), `spec-to-code-compliance` (whitepaper vs implementation), `zeroize-audit`, `constant-time-analysis`, `crypto-audit`.
