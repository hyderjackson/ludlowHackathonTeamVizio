# Methods and reasons

| Step | Reason | Important boundary |
|---|---|---|
| Inspect acr2 and loaded libraries | Tie the observed path to a process and Alphonso adapter | A module name alone does not prove what was transmitted |
| Scoped interception with independent packet recording | Read application messages and check whether proxy silence matches transport silence | Only the selected rooted-device path was decrypted |
| Preserve originals and record hashes | Keep analyses traceable to exact evidence | A hash does not validate the clock or physical source |
| Exclude settling/menu intervals | Reduce transition effects in measured conditions | Manual confirmation does not establish exact toggle latency |
| Live Plus On / Off / On | Change the setting and check that uploads recover | Off2 had a separate session, so it is not an uninterrupted fourth phase |
| Matched normal / silent / audio-only / normal HDMI | Separate picture from soundtrack and check recovery | The test does not distinguish an electronic tap from a microphone hearing speakers |
| Decode every retained record | Check lengths, frame indices, finite values and repeated structure | Parsing is not evidence of backend recognition |
| Execute selected original SDK instructions on synthetic inputs | Check selected semantics beyond names and decompiler guesses | Not a full TV process or complete production audio pipeline |
| Take a bounded shared-source sample | Establish that programme audio was present at the source | Separate from uploaded fingerprints; no exclusion of mixing or ambient pickup |
| Fresh test issuer with retained leaf and trust controls | Connect accepted uploads to the certificate challenge | Full TV trust history and stock behavior remain unresolved |

Requests enter a phase by request start time in a half-open interval `[start, end)`. A response remains associated even if it arrives after that interval. Malformed end messages count as attempts, not accepted fingerprints.

The original analysis used mitmproxy, TShark, copied binaries, Ghidra, and bounded Unicorn experiments. This repository contains offline analysis and instrumentation examples. It does not start an interception session or reproduce the root exploit.
