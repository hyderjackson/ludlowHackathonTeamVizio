# Run metadata

Metadata for the Vizio capture runs behind `FINDINGS.md`. One row per run. This describes
the captures (scenario, settings, size, and which ACR indicators appeared). It does not
include the raw packet CSVs.

Device: Vizio SmartCast `s-viziotv-2`, model `D32fM-K01`, firmware `3.720.9.1-1`, TV IP
`192.168.103.133`. Captured 2026-10-19 on the Mac Internet-Sharing bridge.

Settings columns: ACR = Viewing Data on/off. Ads = ad settings on/off where recorded.
DNS = Do Not Sell My Data on/off where recorded.

Indicator columns: `:5558` = fingerprint stream seen. Inscape = TLS to `*.tvinteractive.tv`
seen. Amagi = program name visible in plaintext Amagi SNI.

| Start (EDT) | Scenario | Source | ACR | Ads | DNS | Packets | Dur (s) | `:5558` | Inscape | Amagi |
|---|---|---|---|---|---|---|---|---|---|---|
| 15:57 | idle | app (none) | on | - | - | 2,273 | 597 | no | no | no |
| 16:58 | WatchFree+ Fox News | WatchFree+ | on | - | - | 226,699 | 599 | yes | yes | no |
| 17:38 | WatchFree+ CNN | WatchFree+ | on | - | - | 290,262 | 600 | yes | yes | no |
| 18:15 | idle | WatchFree+ | off | - | - | 331,299 | 599 | no | no | yes |
| 18:26 | Fox News | WatchFree+ | off | - | - | 227,677 | 599 | no | no | yes |
| 18:36 | CNN | WatchFree+ | off | - | - | 41,302 | 42 | no | no | yes |
| 18:37 | CNN | WatchFree+ | off | - | - | 131,159 | 205 | no | yes | yes |
| 18:45 | CNN | WatchFree+ | off | - | - | 10,317 | 82 | no | no | yes |
| 18:47 | CNN | WatchFree+ | off | - | - | 334,119 | 600 | no | no | yes |
| 19:18 | Fox News | HDMI | off | off | - | 2,457 | 598 | no | no | no |
| 19:34 | Fox News | HDMI | on | on | - | 2,566 | 599 | no | no | no |
| 19:59 | Fox News | YouTube | on | on | - | 180,445 | 598 | no | no | no |
| 20:16 | Sesame Street | kids app | on | on | off | 377,444 | 600 | no | yes | no |
| 20:39 | Sesame Street | kids app | on | on | on | 367,529 | 600 | no | no | no |

Paired same-session test, 2026-10-20:

| Start (EDT) | Scenario | Source | ACR | Ads | DNS | Packets | Dur (s) | `:5558` | Inscape | Amagi |
|---|---|---|---|---|---|---|---|---|---|---|
| 09:43 | Sesame Street | kids app | on | - | - | 286,640 | 480 | no | yes | no |
| 09:52 | Fox News | WatchFree+ | on | - | - | 175,036 | 480 | no | no | no |

Notes:

- Kinesis analytics (`kinesis.us-west-2.amazonaws.com`) appeared in nearly every run
  regardless of setting, so it is not broken out as a column.
- WatchFree+ content is served by Amagi in all WatchFree+ runs. The Amagi column marks the
  runs where the program name was directly visible in the plaintext SNI we sampled.
- Short CNN runs at 18:36, 18:45 were interrupted and restarted, which is why durations
  vary.
- The `:5558` collector handoff described in `FINDINGS.md` section 1a comes from the
  continuous background capture around 16:44, not from one of the rows above.
- The 2026-10-20 pair backs findings 5 and 6. The 09:52 WatchFree+ run streamed 176 MB of
  video but produced no `:5558` and no Inscape, unlike the 2026-10-19 WatchFree+ news runs.
  Its Amagi SNI was not captured in the window, so content was confirmed by the 176 MB
  downstream from the WatchFree+ Fastly CDN.
