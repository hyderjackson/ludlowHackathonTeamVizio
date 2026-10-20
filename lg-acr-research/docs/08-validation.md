# Repository validation

Validated locally on 20 October 2026. No TV/router connection, new capture, rooting action or push formed part of these checks.

- The adapted baseline scripts reproduced 289 requests, 9,826 legacy records and 4,865 V3 vectors from the private original flow file.
- The adapted Live Plus analysis reproduced 215 / 0 / 215 / separate 0, with independent zero TCP 4437 packet counts in both Off windows.
- The HDMI analysis reproduced attempts 46 / 0 / 50 / 45 and acceptances 43 / 0 / 48 / 42, including retained event/playback/packet checks.
- The certificate analysis reproduced 52 attempts and 48 valid accepted fingerprints, including retained certificate/connection and independent trust controls.
- Structural example/tests cover length errors, missing fields, invalid frame relationships, nonfinite values and truncated flow records. Share-boundary tests cover private-run exclusion, raw capture files, symlinks and key markers.
- All Python sources compiled; shell sources passed syntax checks. Playback, clip generation and live instrumentation were not launched during repository preparation.
- The two original SDK harness files were copied unchanged. Their historical selected-instruction results are described in the study; the emulators were not rerun as part of this packaging step.
- Generic share audit plus a private comparison against actual baseline identifier/location values found no matches in selected source/docs. This does not guarantee arbitrary future additions are safe.

Full empirical checks require private inputs, which are not redistributed. Public tests use synthetic data only. Local V3/figure dependency versions: numpy 2.5.4, matplotlib 3.11.2. Dependency ranges in requirements-analysis.txt are not a locked environment.
