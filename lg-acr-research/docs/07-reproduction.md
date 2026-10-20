# Offline reproduction

Run commands from the repository root. These scripts analyze existing local evidence. They never connect to the TV/router. Use a new output directory for each command. Outputs are private and should not be added to Git.

## Inputs

| Analysis | Required retained inputs |
|---|---|
| Baseline | `flows.mitm` from the baseline recording |
| Live Plus | Original combined study TGZ and separate Off2 TGZ; private TV source IPv4 for packet attribution |
| HDMI | Original HDMI TGZ plus the matching local playback JSONL |
| Certificate | Original certificate TGZ; public certificate and event members are selected safely |

The HDMI and certificate analyzers enforce the original archive digest because their checks refer to those exact experiments. This is reproduction of the retained study, not a universal importer for unrelated trials. The baseline parser supports the recorded typed-netstring flow format, not every future mitmproxy version. Treat evidence inputs as private/trusted local artifacts and avoid running these historical scripts on arbitrary hostile archives.

## Commands

Replace the uppercase paths and private attribution values before running:

```bash
python3 reproduce.py baseline --flows BASELINE_FLOWS --features --out /tmp/acr-baseline-review
python3 reproduce.py live-plus --study-archive STUDY_TGZ --off2-archive OFF2_TGZ --tv-ip TV_IPV4 --plot --out /tmp/acr-liveplus-review
python3 reproduce.py hdmi --archive HDMI_TGZ --playback-log PLAYBACK_JSONL --plot --out /tmp/acr-hdmi-review
python3 reproduce.py certificate --archive CERTIFICATE_TGZ --out /tmp/acr-certificate-review
```

`--skip-packets` allows the Live Plus message comparison without TShark/TV-source attribution, but cannot reproduce the independent packet finding or combined figure. `--features` needs NumPy and Matplotlib. TShark and OpenSSL are required for the corresponding full checks. Do not use `python -O`, because original scripts use assertions for evidence validation.

Results appear under the private run's `results/`. Extracted input members, exact features and logs stay under `evidence/`. Some generated summaries retain peer addresses or app/channel values. The share exporter does not include any of these outputs.

## SDK checks

The exact copied binary is not included. The isolated runner requires Linux, Bubblewrap, `timeout`, and a Python environment containing Unicorn:

```bash
bash analysis/sdk/run_isolated.sh PYTHON_ENV_DIRECTORY SDK_BINARY serializer
bash analysis/sdk/run_isolated.sh PYTHON_ENV_DIRECTORY SDK_BINARY quantizer
```

The binary digest is checked. The harnesses have instruction/time bounds, allow selected code ranges, model documented helpers and reject guest syscalls. Bubblewrap removes networking and exposes read-only inputs. These are selected-function experiments on synthetic data, not an execution of the whole TV process. Do not execute the copied ARM binary natively or run `ldd` on it.

## Local HDMI stimuli

Place a lawfully usable `source.mp4` in a new private clips directory. `bash experiments/build_clips.sh PRIVATE_CLIPS_DIRECTORY` creates the normal, silent-picture and black-picture-with-sound clips there, overwriting those generated filenames. It does not validate every matching-frame property; those checks belong in the experiment record. No clip is bundled or downloaded automatically.

`python3 experiments/play_hdmi.py --clips-dir PRIVATE_CLIPS_DIRECTORY --log-dir PRIVATE_LOG_DIRECTORY` starts mpv on the laptop. It does not change display/audio settings. Verify the TV image and HDMI sound physically. Switch clips in the terminal, leaving the player open. A playback interruption invalidates the affected measurement.
