# Fuzzing & Dynamic Test Harnessing Playbook

Coverage-guided and mutation-based dynamic testing to surface memory-corruption,
logic, and crash bugs in parsers, codecs, protocols, and any code that eats
untrusted bytes. Authorized testing only — preserve the remediation framing the
source skills carry (e.g. `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` patches are
test-only and must never ship to production).

## When this applies

Route an engagement here when you see:
- **Untrusted-input boundaries**: file-format parsers (PNG/JPEG/PDF/media/archive),
  protocol handlers (HTTP/DNS/TLS/custom binary), serialization/deserialization
  (`encode`/`decode`, `serialize`/`deserialize`, `loads`/`dumps`, `pack`/`unpack`).
- **Memory-unsafe languages**: C/C++ (and `unsafe` Rust, FFI boundaries, Python C
  extensions) — buffer overflows, UAF, double-free, OOB read/write live here.
- **High cyclomatic-complexity validators** that accept external bytes.
- A target that already ships a `fuzz/` dir, `LLVMFuzzerTestOneInput`, OSS-Fuzz
  `project.yaml`/`build.sh`, or `cargo fuzz` setup — extend it, do not rebuild.
- A request to *measure test quality* (mutation testing) or *prove invariants*
  (property-based testing) rather than just crash-hunt.
- **Injection surface** (web params, LDAP filters, shell-reachable inputs) — use
  the SecLists payload corpora (`security-fuzzing`) as a dictionary/seed source.

## Methodology

1. **Map the attack surface.** Identify entry points that accept external input:
   parsers, validators, protocol/format handlers, crypto/auth routines, anything
   with high branch count. These are your harness targets (harness-writing). Prefer
   parsers first — high bug density, clear entry points, easy to harness.
2. **Pick the engine** by language/goal:
   C/C++ quick start -> **libFuzzer**; multi-core / plateau-breaking -> **AFL++**;
   Rust -> **cargo-fuzz**; Python (+ C ext) -> **Atheris**; custom mutators /
   research -> **LibAFL**; continuous/CI at scale -> **OSS-Fuzz**.
3. **Write a minimal harness**, then iterate. Start with the simplest call to the
   target; add size validation (`if (size < MIN) return 0;`), then structured input
   extraction (`FuzzedDataProvider` / `arbitrary`). Keep targets narrow — one format
   per harness (harness-writing).
4. **Compile with sanitizers.** ASan is standard practice; add UBSan; MSan when
   uninitialized-read bugs are in scope. Disable RSS limits for ASan's ~20TB VM
   reservation (address-sanitizer).
5. **Seed + dictionary.** Provide a representative seed corpus (test-suite inputs,
   real sample files) and a focused dictionary of magic bytes / keywords
   (fuzzing-dictionary). 50-200 entries beats thousands.
6. **Run the campaign** until coverage plateaus, not for a fixed minute count. Run
   for days/weeks; coverage plateaus take time to break (libfuzzer).
7. **Measure coverage** off the *post-campaign corpus* (not live fuzzer stats) to
   assess harness reach and find blockers (coverage-analysis).
8. **Break obstacles.** When coverage stalls behind checksums, magic values,
   crypto sigs, or non-deterministic global state, add a dictionary entry, a seed,
   or a conditional-compilation patch — in that order of preference
   (fuzzing-obstacles).
9. **Triage & verify crashes.** Re-run the saved artifact, confirm reproducibility,
   dedupe by backtrace, and rule out harness-induced false positives (especially
   from obstacle patches). Then write up with severity + CWE.
10. **Quality-gate the tests.** Use mutation testing to find untested logic that
    survived; use property-based testing to assert invariants (roundtrip,
    idempotence) the fuzzer can't express.

## High-signal checklist

Crown jewels — preserve verbatim.

### Harness construction (harness-writing)
- **Minimal C/C++ entry:** `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
- **Minimal Rust entry:** `fuzz_target!(|data: &[u8]| { ... });` (with `#![no_main]`)
- **Always size-guard:** `if (size < MIN_INPUT_SIZE || size > MAX_INPUT_SIZE) return 0;`
- **Structured extraction (C++):** `FuzzedDataProvider fuzzed_data(data, size);`
  then `fuzzed_data.ConsumeIntegral<uint32_t>()` and
  `fuzzed_data.ConsumeBytesWithTerminator<char>(32, 0xFF)`.
- **Structured extraction (Rust):** `#[derive(Debug, Arbitrary)]` on the input
  struct + `arbitrary = { version = "1", features = ["derive"] }`. Note: `arbitrary`
  has no reverse serialization — start from empty corpus (fine for libFuzzer,
  problematic for AFL++).
- **Interleaved fuzzing:** first byte selects op (`switch (mode % 4)`), remaining
  bytes are operands — one shared corpus across related operations.
- **Hard rules:** never `exit()` (use `abort()`); join all threads each iteration;
  reset global state (`global_reset()`/`srand(seed)`); free all allocations; no
  logging in the hot path (target 100s-1000s exec/sec); mock blocking I/O.

### Sanitizers (address-sanitizer)
- **Enable ASan:** `-fsanitize=address` (add `-g` for stack traces, `-O2` for speed).
- **Combine:** `clang++ -fsanitize=fuzzer,address,undefined -g -O2 harness.cc -o fuzz`
- **libFuzzer + ASan RSS fix:** run with `-rss_limit_mb=0`; AFL++ uses `-m none`.
- **Quiet the noise during a campaign:** `ASAN_OPTIONS=detect_leaks=0` (review leaks
  at end); `abort_on_error=1` for fuzzers that need `abort()` over `_exit()`;
  `verbosity=1` to confirm ASan is actually linked.
- **`_FORTIFY_SOURCE` false positives:** compile with `-U_FORTIFY_SOURCE`.
- Report shape: `ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 4`.
  Map to **CWE-122** (heap overflow), **CWE-416** (use-after-free), **CWE-415**
  (double-free), **CWE-787** (OOB write), **CWE-125** (OOB read).

### Coverage analysis (coverage-analysis)
- **Instrument (LLVM):** `-fprofile-instr-generate -fcoverage-mapping` (build at
  `-O2`/`-O0`, **not** `-O3` which deletes code and misleads coverage; do **not**
  combine with `-fsanitize=fuzzer` for the coverage build — it conflicts).
- **Pipeline:**
  `LLVM_PROFILE_FILE=fuzz.profraw ./fuzz_exec corpus/` →
  `llvm-profdata merge -sparse fuzz.profraw -o fuzz.profdata` →
  `llvm-cov show ./fuzz_exec -instr-profile=fuzz.profdata -format=html -output-dir html/`
- **Exclude harness from numbers:** `-ignore-filename-regex='harness.cc|execute-rt.cc'`.
- **Rust:** `cargo +nightly fuzz coverage <target>` (needs `llvm-tools-preview`,
  `cargo-binutils`, `rustfilt`).
- **Crashing inputs kill coverage gen** — `fork()` per file and `waitpid` to isolate.
- Read the report for **magic-value checks** never executed → feed them to a dict.

### Dictionaries (fuzzing-dictionary)
- **Format:** quoted tokens, hex escapes for binary: `kw3="\xF7\xF8"`,
  `png_magic="\x89PNG\r\n\x1a\n"`, bare `"IEND"`.
- **Use:** libFuzzer `-dict=./d.dict`; AFL++ `-x ./d.dict` (multiple `-x` allowed);
  cargo-fuzz `... -- -dict=./d.dict`.
- **Generate:**
  - from headers: `grep -o '".*"' header.h > header.dict`
  - from binary: `strings ./binary | sed 's/^/"&/; s/$/&"/' > strings.dict`
  - from man pages: `man curl | grep -oP '^\s*(--|-)\K\S+' | sed 's/[,.]$//' | sed 's/^/"&/; s/$/&"/' | sort -u > man.dict`
- **AFL++ auto-dict (LTO only):** `export AFL_LLVM_DICT2FILE=auto.dict` then
  `afl-clang-lto++ target.cc -o target` extracts comparison strings at compile time.
- Keep 50-200 focused entries; `sort -u` to dedupe.

### Obstacle bypass (fuzzing-obstacles)
- **Detect:** coverage shows a wall behind a checksum/hash/sig, or `rand()`/`time()`/
  `srand()` global seeding causing non-reproducible crashes.
- **C/C++ bypass macro** (auto-defined by `-fsanitize=fuzzer` and afl-clang-fast):
  ```c
  if (checksum != expected) {
  #ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
      return -1;
  #endif
  }
  ```
- **Rust bypass:** `if checksum != expected { if !cfg!(fuzzing) { return Err(..) } }`
  (cfg set only under `cargo fuzz`, or `RUSTFLAGS="--cfg fuzzing"`).
- **Deterministic PRNG:** `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION srand(12345);`
- **Safe-default over skip** when downstream assumes validated state (avoid the
  classic `100 / config.x` div-by-zero false positive — set `config.x = 1` instead
  of skipping `validate_config`). Effective patches lift coverage 10-50%+.
- **AFL++ input-to-state:** `AFL_LLVM_LAF_ALL` splits multi-byte comparisons; CMPLOG
  (`AFL_LLVM_CMPLOG=1` build + `-c0` run) is the strongest constraint solver available.

### Injection-surface fuzzing (security-fuzzing — SecLists)
- **Special chars seed/dict:** `` ~ ! @ # $ % ^ & * ( ) - _ + = { } ] [ | \ ` , . / ? ; : ' " < > ``
- **LDAP injection payloads:** `*(|(objectclass=*))`, `*(|(mail=*))`,
  `admin*)((|userpassword=*)`, `*)(uid=*))(|(uid=*`, `x' or name()='username' or 'x'='y`
  (CWE-90).
- **Command injection (commix-style)** uses separator-prefixed echo probes with
  arithmetic markers, e.g. `;echo MPCSBG$((54+42))$(echo MPCSBG)MPCSBG` across
  `;`/`&`/`|`/`||`/`&&`/`%0a`/`%3B`/URL-encoded separators (CWE-78). SQLi corpora
  live under `references/Fuzzing/Databases/SQLi/`.

### Mutation testing (mutation-testing — mewt/muton)
- `mewt init` → `mewt mutate [paths]` → `mewt run [paths]`; inspect with
  `mewt print targets`, `mewt status`, `mewt print mutant --id [id]`.
- **Result meaning:** *Caught/TestFail* = good; **Uncaught = surviving mutant =
  untested logic** (the finding you care about); *Timeout* = inconclusive;
  *Skipped* = a more severe mutant already failed that line.
- **Most common misconfig:** mutating non-source (mocks/tests/vendor/generated) —
  scope `[targets].include` to `src/**` and `ignore = ["test","mock","generated"]`.
- **Two-phase speedup** (integration-heavy suites): Phase 1 targeted per-file tests,
  then `mewt results --status Uncaught --format ids > uncaught_ids.txt` and
  `mewt test --ids-file uncaught_ids.txt` against the full suite (~2.5× faster).

### Property-based testing (property-based-testing)
- **Property catalog:** Roundtrip `decode(encode(x)) == x` (HIGH for codec pairs);
  Idempotence `f(f(x)) == f(x)`; Invariant; Oracle `new_impl(x) == reference(x)`;
  Commutativity/Associativity. Strength: No-Exception < Type-Preservation <
  Invariant < Idempotence < Roundtrip — always push past "no crash".
- **Always pin edge cases:** `@example([])`, `@example([1])`, `@example([1,1,1])`,
  `@example("")`, `@example(0)`, `@example(-1)`.
- **Settings:** dev `@settings(max_examples=10)`; CI `200`; release
  `@settings(max_examples=1000, deadline=None)`.
- **Libs:** Python Hypothesis, JS/TS fast-check, Rust proptest/quickcheck, Go rapid,
  Java jqwik, EVM/Solidity **Echidna**/**Medusa** (`echidna_*` invariant fns).
- **False-positive discipline:** a failing property is not automatically a bug —
  ground it against docstring/type/spec, check the *shrunk* minimal input is within
  the documented domain, then report. Classic traps: lone-surrogate `'\uD800'`
  roundtrips, `1e-320` numeric instability, hash/eq contract breaks.

## Tools & commands

```bash
# --- libFuzzer (C/C++) ---
clang++ -fsanitize=fuzzer,address -g -O2 -U_FORTIFY_SOURCE harness.cc target.cc -o fuzz
./fuzz -dict=./format.dict -max_len=4000 -close_fd_mask=3 corpus/
./fuzz -fork=1 -ignore_crashes=1 corpus/          # keep going past crashes
./fuzz -merge=1 minimized_corpus/ corpus/         # minimize corpus
./fuzz -jobs=4 -workers=4 -fork=1 -ignore_crashes=1 corpus/

# --- AFL++ ---
AFL_USE_ASAN=1 afl-clang-fast++ -DNO_MAIN=1 -O2 -fsanitize=fuzzer harness.cc main.cc -o fuzz
afl-fuzz -i seeds -o out -x ./dict.dict -- ./fuzz   # seeds dir must be non-empty
AFL_TMPDIR=/dev/shm AFL_FAST_CAL=1 afl-fuzz -i seeds -o out -- ./fuzz
afl-fuzz -M primary -i seeds -o state -- ./fuzz &    # multi-core: 1 primary
afl-fuzz -S secondary01 -i seeds -o state -- ./fuzz & # + N secondaries
AFL_LLVM_CMPLOG=1 make; afl-fuzz -c0 -S cmplog -i seeds -o state -- ./fuzz
afl-cmin -i out/default/queue -o min_corpus -- ./fuzz
afl-whatsup state/ ; afl-plot out/default out_graph/
# input length -G, timeout -t (ms), mem -m; crashes in out/default/crashes/

# --- cargo-fuzz (Rust) ---
cargo fuzz init ; cargo fuzz add my_target
cargo +nightly fuzz run my_target
cargo +nightly fuzz run --sanitizer none my_target   # 2x faster for safe Rust
cargo geiger                                          # detect unsafe before disabling ASan
cargo +nightly fuzz run my_target -- -dict=./dict.dict -max_len=1024
cargo +nightly fuzz coverage my_target

# --- Atheris (Python) ---
# pure python: @atheris.instrument_func or `with atheris.instrument_imports():`
#   atheris.Setup(sys.argv, test_one_input); atheris.Fuzz()
# C extension build flags:
export CC=clang CFLAGS="-fsanitize=address,fuzzer-no-link"
export CXX=clang++ CXXFLAGS="-fsanitize=address,fuzzer-no-link" LDSHARED="clang -shared"
export ASAN_OPTIONS="allocator_may_return_null=1,detect_leaks=0"
export LD_PRELOAD="$(python -c 'import atheris,os;print(os.path.join(os.path.dirname(atheris.__file__),"asan_with_fuzzer.so"))')"
python fuzz.py corpus/ -max_total_time=600 -max_len=1024

# --- LibAFL ---
# drop-in libFuzzer: build libafl_libfuzzer_runtime/build.sh -> libFuzzer.a
clang++ -DNO_MAIN -g -O2 -fsanitize=fuzzer-no-link libFuzzer.a harness.cc main.cc -o fuzz
./fuzz --cores 0,8-15 --input corpus/ -x png.dict   # multi-core; -tui=1 for TUI
# custom fuzzer: cargo add libafl libafl_targets libafl_bolts libafl_cc; crate-type=["staticlib"]
# tokens: Tokens::from([...]); NewHashFeedback(&BacktraceObserver) dedupes crashes by backtrace

# --- OSS-Fuzz (continuous) ---
git clone https://github.com/google/oss-fuzz && cd oss-fuzz
python3 infra/helper.py build_image --pull <project>
python3 infra/helper.py build_fuzzers --sanitizer=address <project>
python3 infra/helper.py run_fuzzer <project> <harness>
python3 infra/helper.py build_fuzzers --sanitizer=coverage <project>
python3 infra/helper.py coverage <project>
# enroll: project.yaml + Dockerfile (FROM base-builder) + build.sh ($CXX $CXXFLAGS
#   harness.cc -o $OUT/harness $LIB_FUZZING_ENGINE ./libproject.a); python via
#   compile_python_fuzzer; rust via `cargo fuzz build -O --debug-assertions`

# --- Coverage (engine-agnostic) ---
clang++ -fprofile-instr-generate -fcoverage-mapping -O2 main.cc harness.cc execute-rt.cc -o fuzz_exec
LLVM_PROFILE_FILE=fuzz.profraw ./fuzz_exec corpus/
llvm-profdata merge -sparse fuzz.profraw -o fuzz.profdata
llvm-cov report ./fuzz_exec -instr-profile=fuzz.profdata -ignore-filename-regex='harness.cc'
gcovr --gcov-executable "llvm-cov gcov" --exclude harness.cc --html-details -o coverage.html
```

## Expert gotchas / bypasses

- **Coverage build ≠ fuzzing build.** Don't compile the coverage binary with
  `-fsanitize=fuzzer` (conflicts with profile instrumentation) and don't use
  `afl-clang-fast`/`hfuzz-clang` for coverage — use stock clang/gcc with the
  profile flags (coverage-analysis). Likewise `-O3` deletes code and lies; use `-O2`.
- **Non-reproducible crash = look at the harness, not the bug.** Almost always
  global state, `rand()`/time, threads not joined, or reading `/dev/urandom`. Reset
  globals, seed PRNG from input, mock the clock (harness-writing).
- **ASan "kills process immediately" on start** is the 20TB VM reservation, not a
  real crash — `-rss_limit_mb=0` (libFuzzer) / `-m none` (AFL++), never use `-m`
  with ASan on AFL++.
- **Stability < 85% in AFL++** means non-determinism; switch to stdin/file fuzzing
  or fix the source. Low exec/sec (<1k) means you're not in persistent mode — use an
  `LLVMFuzzerTestOneInput` harness.
- **Obstacle patches manufacture false positives.** Skipping `validate_config`
  then dividing by `config.x` is a *fuzzing-only* crash. Always assess whether
  downstream code assumes the skipped invariant; prefer safe defaults over a blind
  `#ifndef ... return`. Document every patch — it must never reach production
  (the macro is literally named `..._UNSAFE_FOR_PRODUCTION`).
- **`arbitrary` can't reverse-serialize**, so a structure-aware Rust harness can't
  consume an existing byte corpus deterministically — great for libFuzzer's empty
  start, painful for AFL++ seed reuse (harness-writing).
- **Rust + OSS-Fuzz: only AddressSanitizer is supported with libFuzzer** — don't
  promise UBSan/MSan coverage on enrolled Rust projects (ossfuzz).
- **Safe Rust barely benefits from ASan** (compiler already prevents the bugs) —
  `cargo geiger` first; if no `unsafe`/FFI, run `--sanitizer none` for 2× speed.
- **Atheris segfault with no ASan report** = `LD_PRELOAD` not set to
  `asan_with_fuzzer.so`; and you must `instrument_imports()` *before* importing the
  target or coverage is zero.
- **Dictionaries help magic bytes, not checksums.** A 4-byte CRC has ~1/2^32 odds
  of being guessed — that needs an obstacle patch or CMPLOG, not a dict entry.
- **Measure coverage on the post-campaign corpus, never the live fuzzer counter** —
  different engines count edges differently, so live stats aren't comparable across
  tools (coverage-analysis).
- **Mutation testing's killer signal is the *surviving* mutant**, not the kill
  rate; and watch you didn't mutate mocks/generated code (inflates survivors).
- **A failing property is a hypothesis, not a verdict.** Ground against the
  docstring/type/spec and confirm the shrunk input is in-domain before filing —
  the lone-surrogate and `1e-320` cases are the canonical false alarms.

## Delegate to

- **harness-writing** — use when authoring/repairing any fuzz target, handling
  structured inputs (`FuzzedDataProvider`/`arbitrary`/protobuf), or chasing
  non-reproducible crashes.
- **libfuzzer** — use for quick single-target C/C++ campaigns and as the canonical
  `LLVMFuzzerTestOneInput` reference (incl. libpng worked example).
- **aflpp** — use for multi-core campaigns, persistent mode, CMPLOG/RedQueen,
  argv/stdin/file fuzzing, and breaking a libFuzzer plateau.
- **cargo-fuzz** — use for any Cargo/Rust target, `arbitrary` structure-aware
  fuzzing, and the safe-vs-unsafe sanitizer decision.
- **atheris** — use for pure-Python or Python-C-extension fuzzing and its
  `LD_PRELOAD`/ASan-preload setup.
- **libafl** — use for custom mutators/feedback, backtrace-based crash dedup,
  auto-tokens, or research-grade fuzzer construction.
- **ossfuzz** — use to set up continuous fuzzing, run/reproduce an enrolled
  project's harness locally via `helper.py`, or author `project.yaml`/`build.sh`.
- **address-sanitizer** — use for ASan/UBSan/MSan flag selection, `ASAN_OPTIONS`
  tuning, and decoding sanitizer crash reports into CWEs.
- **coverage-analysis** — use to baseline/track coverage, build the execute-rt
  runtime, and locate magic-value blockers.
- **fuzzing-dictionary** — use to build or auto-extract format dictionaries.
- **fuzzing-obstacles** — use when checksums, crypto sigs, PRNGs, or multi-stage
  validation wall off coverage; covers the conditional-compilation patch patterns.
- **security-fuzzing** — use for injection-payload corpora (SQLi/LDAP/command-
  injection/special-chars) as seeds or dictionaries against web/parser surfaces.
- **mutation-testing** — use to configure/optimize a mewt/muton campaign and find
  surviving-mutant coverage gaps.
- **property-based-testing** — use to assert roundtrip/idempotence/invariant
  properties, design generators, and triage PBT failures vs genuine bugs.
