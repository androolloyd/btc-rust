# btc-rust development

Read `docs/BUILD_PLAN.md` and `docs/REVIEW.md` before selecting repair work.
The user authorized autonomous repository review, bug fixes, and replacement
of placeholder implementations. Prioritize BIP transport and wallet crypto,
then the remaining runtime backends. Resolve routine choices without asking.

- Preserve user changes and existing test artifacts; inspect Git status first.
- Trace runtime callers and use primary Bitcoin specifications/Core sources.
- Use independent vectors or meaningful regressions for consensus/crypto changes.
- A passing self-roundtrip does not establish protocol interoperability.
- Never replace missing verification with success, fabricated data, or a hash
  that only resembles a curve key. Report unsupported behavior explicitly.
- Proposed consensus rules remain explicit experiments; do not activate them
  on ordinary networks merely because a BIP is marked Complete.
- Batch each coherent set of changes before running tests, as the user requested
  to save time. Use `./scripts/check.sh` as the final local gate, with focused
  follow-up checks only for failures or unresolved concerns. Keep `Cargo.lock`
  synchronized with dependency changes.
- Update the build plan with actual acceptance results and remaining work.
- The user authorized keeping the repository updated without pull requests.
  Review changes yourself and commit verified milestones to
  `codex/review-bip-runtime-fixes`. Do not create PRs or require user review.
  Direct updates to `main` and closing the existing draft are pending explicit
  authorization after automatic approval review rejected those actions.
  Preserve unrelated user changes. Use normal pushes; do not force-push.
  Main integration, releases, deployment and external messages need separate
  authorization.
- When SSH authentication is unavailable, use authenticated HTTPS with the
  GitHub CLI credential helper; never print or embed raw access tokens.

The workspace uses Rust 1.88 and has twelve library/binary crates. The fuzz
workspace is separate and uses nightly for sanitizer runs.
