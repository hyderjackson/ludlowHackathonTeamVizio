# Findings

## Device and access

LG 24LB7000PUA, firmware 43.04.24, internal webOS 11.0.1-9104 (described as webOS 26). Copied configuration/release files corroborate those values; a physical-label check was not independently performed. A prior SlopBro v0.1.0 session reported success and Homebrew Channel subsequently showed root status ok. This study used that existing access. It did not discover the rooting exploit.

## Results

| Experiment | Measured result | Interpretation |
|---|---|---|
| Live Plus | On1 215, Off1 0, On2 215, separate Off2 0 fingerprint messages | Off suppressed the monitored path and On restored it |
| Independent packets | Zero TCP 4437 packets in both Off windows, other TV traffic continued | Application silence was corroborated independently |
| HDMI audio isolation | Attempts 46 / 0 / 50 / 45; accepted 43 / 0 / 48 / 42 | Soundtrack removal suppressed fingerprints; moving picture was unnecessary for this path |
| Payload validation | 289 accepted baseline messages, 9,826 legacy records, 4,865 V3 vectors | Live fields agree with selected SDK/layout interpretation |
| Separate source sample | Eight seconds of programme audio, identified by listening | Programme audio was present in the sampled source; no network WAV was recovered |
| Fresh certificate | 48 valid messages accepted during the separate challenge | Authentication weakness on the rooted uploader/path, with stock behavior unresolved |

HTTP 202 means accepted for processing, not successful recognition. Off2 is a separate follow-up with a gap and restarted proxy. The HDMI silent phase had 53 TCP 4437 packets and 465 other TV packets, despite zero fingerprint POSTs. Neither result says all TV tracking stopped.

Machine-readable selected aggregates: [results.json](../data/public/results.json).
