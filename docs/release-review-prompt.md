# anykms 0.1.0 pre-release review

Use a workflow (multi-agent orchestration) for this review. It calls for roughly 20–30 agents;
the phases and the agents each one needs are listed below.

## Goal

anykms is about to publish its first release, 0.1.0. Review the whole project and decide what
must change **before** the publish because changing it later is expensive, and what can wait.

The question every finding must answer is: **what does it cost to change this after 0.1.0?**
Classify each finding by how reversible it is:

| Class | Meaning | Examples |
|---|---|---|
| `ONE-WAY` | Data or contracts that outlive the code. Effectively permanent. | Envelope wire format, Azure framed ciphertext, AAD → AWS encryption-context encoding, JWS/JWKS output, URI schemes, env var names, crate names |
| `BREAKING` | Public Rust API or Cargo feature changes. Possible in 0.2, but every user pays. | Trait shapes, type and method names, error kinds, feature names, public dependencies |
| `ADDITIVE` | Can ship in 0.1.x. | New methods, new recipes, new backends |
| `DOCS` | Documentation only. | |

`ONE-WAY` and `BREAKING` findings matter most. Do not spend effort on `ADDITIVE` polish while
an open question remains in the first two classes.

## Ground rules

- **Question anything, past decisions included.** `docs/PLAN.md`, `docs/review-plan.md`,
  `docs/cloud/review-*.md` and `docs/cloud/*-plan.md` record earlier decisions and their
  reasons. You may challenge any of them. When you do, label the finding `CHALLENGE`, cite the
  decision, state its recorded reason, and explain why that reason is wrong or no longer holds.
  The judges reject a challenge that does not engage with the recorded reason.
- **Do not re-report settled items** unless you are challenging them. The Phase 0 brief lists
  them.
- **Read-only on the repository.** Do not edit code or docs, except for the final report. Put
  experiments in scratch crates outside the workspace (`$TMPDIR/anykms-review/`) or in a git
  worktree.
- **Evidence or it did not happen.** Cite `file:line`, compiler output, test output or a vendor
  documentation URL. Mark claims about vendor behavior you could not check as `UNVERIFIED`.
- **No style nits on internals.** Internal code quality matters only where it affects users,
  security, or the cost of maintaining the public contract.
- **Local services only, no cloud credentials.** `docker compose up` (see `compose.yaml`) runs
  Vault, OpenBao (plain, TLS and sealed), LocalStack and floci for AWS, and Lowkey Vault for
  Azure. There is no GCP emulator; GCP is reviewed from code, docs and mocks.

## Finding schema

Every reviewer reports findings in this shape:

```
id:              <lens>-<n>, e.g. API-7
title:           one line
claim:           what is wrong, one or two sentences
evidence:        file:line, command and output, URL
affected:        public items, features, formats or docs
reversibility:   ONE-WAY | BREAKING | ADDITIVE | DOCS
user_impact:     who hits it, how often, how bad
proposed_fix:    concrete; include the alternatives you considered
effort:          XS (<1h) | S (half a day) | M (1–3 days) | L (more)
challenges:      the PLAN / review decision it challenges, or none
confidence:      high | medium | low
```

## Phase 0: shared brief (1 agent)

Build a fact sheet in `$TMPDIR/anykms-review/brief/` so the other agents do not each rediscover
it:

1. **Public API surface** per published crate, from `cargo public-api` (install it if missing)
   or rustdoc JSON, with all features on. Save the full listing plus item counts per crate.
2. **Cargo features** per crate and for the facade: defaults, what each enables, and which
   combinations are mutually exclusive or fail at run time instead of compile time.
3. **Public dependencies**: every foreign type that appears in the public API, with crate and
   version (`rustls`, `rsa` 0.10 RC, `secrecy`, `zeroize`, `http`, `reqwest`, …).
4. **External contracts**: every wire or persisted format, URI scheme, env var, `ErrorKind`,
   tracing field name, HTTP status mapping and capability bit a user could come to depend on.
5. **Build cost**: dependency count, clean build time and `aws-lc-sys` / C-toolchain
   requirements for `anykms` with default features, `features = ["local"]` and all features.
6. **Settled decisions**: one line each, with its source and recorded reason, from PLAN.md, the
   review docs and the CHANGELOG.
7. **Baseline**: fmt, clippy, tests, docs and `cargo package --workspace --exclude
   anykms-testkit --locked`. Report the results; do not fix anything.

## Phase 1: review lenses (6 agents in parallel)

Each agent gets the brief and one lens.

**A. API design and Rust idioms.** Check against the
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html), citing
checklist IDs (C-CASE, C-CONV, C-COMMON-TRAITS, C-SEND-SYNC, C-GOOD-ERR, C-DEBUG, C-SEALED,
C-STRUCT-PRIVATE, C-BUILDER, C-FEATURE, C-STABLE, …). Then:
- Capability traits, the `Dyn*` mirror traits, `trait-variant` and `Send` bounds, dyn
  compatibility, and generic bounds that produce unreadable compiler errors.
- Which traits third parties are meant to implement. Seal the rest.
- `#[non_exhaustive]` on every enum and struct that will grow.
- Constructors: fallible, panicking or builder, and whether that choice is consistent.
- Naming consistency across backends, modules and re-exports. Is there one canonical path per
  item? What does the prelude contain, and is a glob import of it safe?
- `Error` / `ErrorKind`: source chains, `Display` text, classification helpers, no secrets.
- Handles: cost of `Clone`, `Arc` versus owned, `Send + Sync + 'static`.
- **What to cut.** List the public items with the weakest case for being in 0.1.0, and say
  whether each should become `pub(crate)`, move behind an `unstable` feature, or be removed.
  A smaller surface means less to break later.

**B. Semver and release engineering.**
- Public dependencies, especially the `rsa` release candidate and `rustls` 0.23.
- Feature additivity and unification hazards: two TLS providers both on, no RSA backend, a
  feature pulled in by an unrelated dependency.
- Default features, the MSRV policy, and crate metadata (description, keywords, categories,
  `[package.metadata.docs.rs]`, `doc_cfg` badges).
- The crate split. Are 10 published crates right for 0.1? Should `anykms-http` be published as a
  public crate at all? Is the stability promise for `anykms-conformance` clear?
- Lockstep versioning, the CHANGELOG, `cargo-semver-checks` configuration, `SECURITY.md` and a
  disclosure policy, license files in every crate, and a yank plan.

**C. Security and misuse resistance.** Focus on how the API can be misused; earlier reviews
covered the cryptography itself. Can a user easily do the wrong thing?
- AAD handling and key confusion: a signing key used as a KEK, the wrong key opened by URI.
- Fail-open paths, and the local backend reaching production
  (`allow_ephemeral_local_keys`).
- Secrets in `Debug`, error text or tracing; zeroization; TLS and redirect handling.
- Credential-chain surprises: env var precedence, lazy failures, the Azure host allowlist.
- JWS/JWKS verification pitfalls such as algorithm confusion.
- The status of the envelope format's pending external review (a release gate).
- Is there a threat model a user can read?

**D. Operability and runtime.**
- Async runtime coupling: what requires tokio? Cancellation safety. A blocking or sync story.
- Timeout defaults. Retries on non-idempotent operations. One retry budget per registry.
- Connection and client sharing across handles; credential refresh under concurrency.
- Observability: are the tracing fields enough? Is there a metrics hook?
- Is the error classification useful for real decisions (retry, alert, 4xx/5xx)?
- Cost and failure modes of `with_default_providers()`, and behavior when a backend is down.

**E. Docs and onboarding.**
- Run every README and rustdoc snippet. Does each one still match the code?
- Rustdoc coverage, and how docs.rs renders feature-gated items.
- Does each crate's top-level doc say when to use that crate?
- Glossary consistency: KEK, key wrap, data key, handle, provider, registry.
- Can an operator configure each backend from `docs/operations-*.md` alone?
- Do error messages point at the fix?

**F. Scope and sustainability.** Review this with a solo maintainer in mind.
- The in-house HTTP clients, SigV4 signing, credential chains, CRC32C checks and Azure framing:
  how much long-term maintenance and security liability do they carry, compared with depending
  on the vendor SDKs? (PLAN §28 and `docs/cloud/credentials-plan.md` record the current answer.)
- What is the smallest 0.1.0 that delivers the core value? Could a backend or a recipe ship
  later instead?
- Test-suite cost, CI cost, and how fragile the emulator-based tests are.

## Phase 2: black-box usability trials (4 agents in parallel)

Each agent plays a persona and may read **only** what a crates.io user would see: the README,
`cargo doc` output and `crates/anykms/examples/`. **Do not read crate sources.** Write a fresh
crate under `$TMPDIR/anykms-review/<persona>/` that depends on the workspace by path, and run
it against the compose services where the task allows.

Keep a friction log for every task:
- every compiler error, verbatim, and how long it took to resolve;
- every lookup, with where the answer was found (or that it was not found);
- every place you had to guess;
- steps to first success, and lines of code;
- surprises.

Score each task from 1 (gave up) to 5 (obvious). Then write the same core task with the closest
alternative (the vendor SDK used directly, or Tink or the AWS Encryption SDK in pseudocode) and
compare the two.

1. **Application developer, intermediate Rust.**
   - Encrypt a database column, using the local backend in development and Vault in
     production, picked by configuration.
   - Rotate the KEK and rewrap the stored rows.
   - Share the `Registry` across axum handlers.
   - Map anykms errors to HTTP responses.
2. **Platform or identity engineer.**
   - Run a JWT issuer that signs with a KMS key (AWS on LocalStack, or Vault).
   - Publish a JWKS and verify tokens with `jsonwebtoken`.
   - Rotate the signing key with an overlap period.
   - Issue and check HMAC API tokens.
3. **Library or backend author.**
   - Implement a toy third-party backend as a `Provider`, register it and run
     `anykms-conformance` against it.
   - Write a decorator layer, for example metrics.
4. **Test author and ops engineer.**
   - Unit-test an application that uses anykms, with no network.
   - Inject failures to exercise the retry and error paths.
   - Use anykms from a synchronous CLI.
   - Migrate data from a Vault KEK to an AWS KEK with `EnvelopeKeyring`.

Each persona also files findings in the schema above for anything the friction log shows.

## Phase 3: comparison with similar libraries (2 agents in parallel)

Use web research with primary sources: official docs, source code, and changelogs or issue
trackers.

- **Rust:** `aws-sdk-kms`, the official Google Cloud and Azure Rust SDKs for KMS and Key
  Vault, `vaultrs`, `kms-aead`, `tink-rust`, and any multi-KMS crate you find.
- **Other languages.** These are the real benchmark, because Rust has no strong equivalent:
  - Google Tink: KMS clients, envelope AEAD, keysets;
  - AWS Encryption SDK: keyrings, multi-KEK, data-key caching, key commitment, message format;
  - Go CDK `gocloud.dev/secrets`: URL openers;
  - HashiCorp `go-kms-wrapping`;
  - sigstore `pkg/signature/kms`: its `hashivault://`, `awskms://`, `gcpkms://` and
    `azurekms://` URI schemes;
  - SOPS key groups;
  - .NET Data Protection with Azure Key Vault.

Compare on these axes, plus any you find that matter:

| Axis | Questions |
|---|---|
| Capability coverage | Which operations does each one expose per backend? |
| Key addressing | URI scheme, compatibility with existing schemes, versions and aliases |
| Envelope format | Interoperability, key commitment, multiple KEKs, streaming, versioning |
| Credentials | Discovery chain, refresh, workload identity |
| Reliability | Retries, timeouts, caching, rate limits |
| Errors | Model and classification |
| Testing | Fakes and in-memory backends for users' own tests |
| Extensibility | Third-party backends and decorators |
| Runtime model | Async, blocking, runtime coupling |
| Cost to adopt | Dependency weight, build time, binary size |
| Hygiene | Secret handling, FIPS |
| Docs | Quality and examples |
| Project health | Maintenance activity, adoption |

For each axis, say where anykms is better, worse or equal, with evidence. Then cover two more
things:
- **Lessons from their history.** Which breaking changes did these libraries have to make
  (for example, the AWS Encryption SDK's move to key commitment, Tink's API redesigns), and is
  anykms exposed to the same?
- **What to borrow before 0.1.0**, with priority on `ONE-WAY` decisions. For example: should
  anykms accept sigstore-compatible URIs? Should the envelope commit to the key?

## Phase 4: consolidation (1 agent)

Merge duplicate findings across lenses and personas, keep the strongest evidence, and record
which sources reported each finding. Agreement between independent reviewers is a signal, not
proof. Cross-check the findings against the settled-decisions list from Phase 0.

## Phase 5: judge panel

Findings that the consolidator rates Blocker or Should-fix get **three independent judges**.
They do not see each other's verdicts. Lower-rated findings get the Verifier only. Send each
judge batches of about eight findings.

1. **Verifier.** Is it true? Reproduce it: compile a snippet, run a test, read the code.
   Verdict: `CONFIRMED`, `PLAUSIBLE` or `REFUTED`.
2. **Maintainer's advocate.** Steelman the current design using PLAN.md and the recorded
   decisions. What is the strongest reason the code is right as it is? What does the fix cost
   and risk?
3. **User and release advocate.** Will a real user hit this in the first six months? Is the
   reversibility class right? Compare the cost of fixing it now with the cost later.

A **chair** (1 agent) aggregates the verdicts:
- Drop `REFUTED` findings.
- Where the two advocates disagree on something `ONE-WAY` or `BREAKING`, do not decide. Mark it
  `DECISION NEEDED`, with the options, the tradeoff and a recommendation for the maintainer.
- Assign the final severity:

| Severity | Meaning |
|---|---|
| **Blocker** | A `ONE-WAY` or `BREAKING` problem likely to need changing, a security issue, or a documented quick-start path that does not work |
| **Should-fix before 0.1.0** | `BREAKING` and cheap now, or real friction for most users |
| **0.1.x** | `ADDITIVE` |
| **Later** | 0.2 or 1.0 material |
| **Rejected** | Kept in the report with the reason, so it is not raised again |

A panel that accepts nearly every finding has failed. Judges are expected to reject or
downgrade a large share.

## Output

Write `docs/release-review.md`, in the style of `docs/review-plan.md`:

1. **Verdict.** One paragraph: ship, ship after the blockers, or not ready.
2. **Scorecards.** Each lens from 1 to 5 with one sentence; each usability task's score; a
   one-line comparison verdict per axis.
3. **Decisions needed.** Options, tradeoffs and a recommendation for each.
4. **Findings by severity:** Blocker, Should-fix, 0.1.x, Later. Each entry has its id, title,
   sources, evidence, reversibility, fix sketch, effort, and the judges' verdicts with a
   one-line reason each.
5. **Rejected**, with reasons.
6. **Appendices:** friction logs, the full comparison matrix, and the API surface statistics.

Do not change any code. The report is the only deliverable.
