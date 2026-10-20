# Code map

| Location | Role | Private inputs required |
|---|---|---|
| `analysis/common/inspect_flows.py` | Original typed-netstring flow reader and decompression helpers | Local mitmproxy flow file |
| `analysis/common/fingerprints.py` | Small reusable structural validator derived from the full checks | JSON body or synthetic example |
| `analysis/baseline/` | Legacy layout statistics and V3 structure/figure checks | Original baseline flow file |
| `analysis/live_plus/` | Phase-bound request comparison, independent packet counts, figures | Original study and separate Off2 archives |
| `analysis/hdmi/` | Four-phase source isolation analysis, event/packet/playback checks | Original HDMI archive and playback log |
| `analysis/certificate/` | Certificate/connection/upload linkage and OpenSSL controls | Original certificate archive |
| `analysis/sdk/` | Original selected-instruction serializer and Haar/quantizer harnesses | Exact copied SDK, supplied privately |
| `experiments/` | Local matched-clip construction and mpv playback | A privately supplied source clip |
| `instrumentation/` | Sanitized mitmproxy counters and presented-certificate hooks | Separate scoped setup and private runtime directory |
| `tools/` | Structural demo and audited share export | No TV access |
| `tests/` | Reject malformed structures and invalid V3 relationships | Synthetic data only |

## Portability edits

Original scripts had workspace paths, archive labels and one private TV address/MAC. Copies here use explicit local inputs through `reproduce.py`, neutral archive labels, and private runtime directories. The packet checker takes source attribution values at runtime. The verbose route-printing command from the original parser is omitted. Playback requires explicit clip/log directories. Addons require `ACR_EVENT_DIR` rather than writing beside their source.

The counting, record-layout, phase-window, event and certificate-linkage calculations remain the original research logic. Original-script digests are in SOURCE_MAP.json. The two SDK harness files are unchanged. A Python optimization flag would disable their assertions, so do not use `python -O`.

Ghidra/Thumb work also informed interpretation. The copied SDK SHA-256 required by the harness is `87adb105fddca9f7a704676d12426ebee9ac59202567924c0df184057e5315ad`. Relevant selected functions include SessionV1 signature/serialization, Haar/quantization and SessionV3 frame processing. Decompiler output and binaries are not included; bounded harnesses do not prove a complete end-to-end runtime path.
