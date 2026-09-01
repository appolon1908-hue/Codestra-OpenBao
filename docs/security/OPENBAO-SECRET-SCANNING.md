# OpenBao secret scanning

Both the working tree and complete Git history are scanned. The repository
scanner rejects credential shapes, standard private-key headers, secret-file
suffixes, binary content and symbolic links. Gitleaks runs with redaction and
default rules across `--all` refs.

There is one exact false-positive allowlist. The historical value
`15m-default-1h-maximum` in `codestra/runtime-v1/desired-state.json` describes a
database lease-duration policy; it is not a credential. The allowlist binds
both the complete value and exact path and does not suppress any other value in
that file. Platform Security reviewed it on 2026-09-01. Broad path, commit,
rule, entropy or test-directory exclusions are prohibited.

Findings must be redacted in CI. Secret values must never be uploaded as scan
artifacts. A confirmed credential requires revocation first, history-impact
assessment, and a separately approved history-rewrite decision; deleting only
the current file is not remediation.
