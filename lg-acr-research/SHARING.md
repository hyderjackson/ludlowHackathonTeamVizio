# Sharing this repository

This folder contains code, documentation, aggregate measurements and one synthetic message. It contains no raw flow archives, packet captures, device keys, certificate keys, audio recordings, video clips, vendor binaries or full video transcripts.

Use `python3 tools/audit_share.py` before sharing. Use `tools/export_share.py` to make an allowlisted ZIP instead of archiving the entire working directory. Generated analysis outputs belong outside the repository or in ignored `private-runs/`.

The audit detects common secret/address/file patterns. It is a check, not a guarantee for arbitrary new content. Review any newly added file yourself. Generated summaries may include peer addresses, source content information, timestamps or capture hashes even when they omit request bodies. Keep those outputs private until reviewed.

The root method, model, firmware and public research references are context, not an exploit-distribution package. Operational TV/router launchers and rooting payloads are intentionally excluded. The instrumentation addons record counters/certificate evidence but do not establish the network interception scope by themselves. Any live deployment requires a separately reviewed device-specific setup.

The repository has no remote configured. Initializing Git or exporting a ZIP does not send data anywhere. Decide separately whether to release the code, evidence or certificate finding publicly. No organizer or vendor disclosure is implied by this package.
