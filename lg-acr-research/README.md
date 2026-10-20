# Inside LG ACR: code and evidence guide

An offline companion to a case study of one rooted LG TV. Start here if you are reviewing the presentation or asking how the findings were checked.

## Reading order

1. [Findings](docs/01-findings.md): what the experiments established.
2. [Methods](docs/02-methods.md): what changed in each experiment and why.
3. [Payload decoding](docs/03-decoding.md): the record layouts and their limits.
4. [Code map](docs/04-code-map.md): which scripts support which claims.
5. [Limitations](docs/05-limitations.md) and [public references](docs/06-references.md).

## Main results

- Live Plus: **215 / 0 / 215 / separate 0** measured fingerprint messages. Independent packet checks agreed while other TV traffic continued. Off2 followed a gap and a restarted proxy.
- HDMI: accepted fingerprints **43 / 0 / 48 / 42** for normal playback, silent picture, black picture with sound, then normal playback again. Fingerprint attempts were **46 / 0 / 50 / 45**. Silent video still had other traffic.
- Baseline: 289 accepted fingerprint messages. All 9,826 legacy records and 4,865 V3 vectors passed the retained layout checks.
- Certificate challenge: 48 valid messages accepted through a fresh test certificate on the rooted setup. The procedure installed no test CA on the TV. This does not establish stock-device behavior.

The transmitted fields contain lossy audio signatures and metadata. The separate local eight-second recording contained TV programme audio. Built-in microphone capture, video uploads, consent bypass, offline queues and standby collection remain unproved.

## Quick demo, without TV access or private data

Python 3.11+ is sufficient for the structural example and tests:

```bash
python3 tools/inspect_message.py data/examples/synthetic-fingerprint.json
python3 -m unittest discover -s tests -v
python3 tools/audit_share.py
```

The example is synthetic. It demonstrates parsing, not replication of a real soundtrack or server recognition. The original analysis scripts are included with portability edits. Their source hashes appear in [SOURCE_MAP.json](SOURCE_MAP.json).

## Rerunning the original evidence

See [offline reproduction](docs/07-reproduction.md). Private captures are deliberately absent. Analyses read local files only and write into a new private output directory. They do not SSH, contact a TV, replay requests, or change network settings.

Optional dependencies for full analysis are listed in [requirements-analysis.txt](requirements-analysis.txt). TShark and OpenSSL are separate system tools. Original vendor binaries are not redistributed.

## Sharing

Read [SHARING.md](SHARING.md), then create an allowlisted bundle:

```bash
python3 tools/export_share.py --out /tmp/lg-acr-research-code.zip
```

The exporter audits the selected files and includes a SHA-256 manifest. It excludes Git internals and private outputs. No remote is configured and nothing is pushed by these tools.

A blanket publication license has not been selected. See [THIRD_PARTY.md](THIRD_PARTY.md) before republication.
