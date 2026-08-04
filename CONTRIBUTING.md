# Contributing to OAB v2

OAB is a security-sensitive benchmark. Changes must preserve comparability, public safety, and evidence integrity.

## Development contract

1. Open an issue describing the construct or defect.
2. Write failing tests before implementation.
3. Derive verifier expectations only from public fixture, task, schema, and policy data.
4. Never add real credentials, private provenance, organization-specific names, or production side effects.
5. Keep matched approved/prohibited variants balanced; blanket action and blanket refusal must both fail.
6. Do not change a released case, fixture, gate, scoring rule, or default repetition count without a new benchmark version.
7. Keep run outputs outside the repository.

## Required checks

```bash
python3 tools/generate_fixtures.py
python3 -m unittest discover -s tests -v
python3 -m oab.public_scan . --denylist /path/to/private-denylist.txt
```

Linux release candidates must execute the live Bubblewrap + libseccomp path and pass the active network and process-creation probes. macOS-only policy construction is not Linux validation.

## Pull-request evidence

Include:

- RED and GREEN test commands;
- public scan output;
- affected cases/gates;
- scoring or comparability impact;
- one sealed evidence verification when execution changed;
- independent code/security review for runner, broker, sandbox, verifier, or scoring changes.

Release-candidate approval must be recorded outside the release tree as `oab.release-approval/v1`, with distinct security and product reviewers approving the exact frozen tree digest. Publish the approval-file digest independently before using it for an authority-eligible run.

Do not include credentials, raw auth files, external run roots, or provider-private receipts.
