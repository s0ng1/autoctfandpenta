# GitHub Update Summary

## Title

IntentLang Phase 1 closure: runtime stabilization, Word-only reporting, CTF flag validation, and e2e coverage

## Summary

This update closes out the current IntentLang Phase 1 work.

Key changes:

- added the internal `intentlang` runtime bootstrap path
- switched the main runtime to artifact-first execution
- added structured `toolset.intentlang` access for metadata and artifact operations
- narrowed pentest reporting to the Word docx path only, without requiring a private template file
- added `verified_findings` upsert / dedup / merge behavior
- tightened CTF completion rules so only `flag{...}` / `FLAG{...}` count as a real flag
- added screenshot recovery for pentest reports from `candidate_evidence`
- added repo-native end-to-end tests for both `ctf` and `pentest`

## User-Facing Impact

- `pentest` now always ends with a `.docx` report
- `final_report_reference` is the canonical final output pointer
- non-standard CTF strings no longer count as final success
- verified pentest findings can carry screenshots directly or inherit them from `candidate_evidence`

## Validation

```bash
./.venv/bin/python -m unittest -v tests.test_intentlang_e2e
./.venv/bin/python -m compileall intentlang meta-tooling/toolset/src/toolset tests/test_intentlang_e2e.py
```

## Suggested Release Notes

- complete IntentLang Phase 1 closure
- stabilize artifact-first pentest / CTF runtime flow
- enforce Word-only pentest reporting
- enforce strict CTF flag format validation
- improve report evidence screenshots
- add repo-native end-to-end regression coverage
