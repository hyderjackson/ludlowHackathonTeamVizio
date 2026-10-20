# Vizio SmartCast / VIZIO OS — Evidence-Based Findings

**Document date:** 2026-10-19 (America/New_York)  
**Investigation goal:** Determine what is actually established about the TV's software, exposed interfaces, Chromium isolation, and feasibility of native/Linux access.  
**Scope:** Evidence visible in this conversation and the available excerpts of earlier conversations in the same project. This is **not** a complete forensic acquisition or an exhaustive export of all prior chats.

> **Evidence rule:** A result observed in an actual pasted response or code excerpt is marked **Observed**. A statement repeated from an earlier summary without its underlying log is marked **Reported, not independently verified**. Results obtained on another TV are **External-only** and must not be attributed to this device. Unknown means **not established**, not "false" or "patched".

## 1. Executive status

| Question / property | Current status | Evidence |
| --- | --- | --- |
| Firmware version | **Observed:** `3.720.9.1-1` | E-01 |
| SCPL version | **Observed:** `3.4.3-2614.0002` | E-01 |
| ACR component version | **Observed:** `3.5.1106` | E-01 |
| Service reached on TCP 7345 | **Observed:** HTTPS request returned an HTTP/2 response | E-02 |
| HTTP server | **Observed:** `lighttpd/1.4.67` in the HTTP response header | E-02 |
| `/install` behavior with invalid POST input | **Observed:** HTTP `500` and `Unhandled Exception` HTML | E-02 |
| Chromium version | **Reported:** Chromium 108; raw user-agent/build output is not included in available excerpts | C-01 |
| CPU architecture | **Reported:** 32-bit ARM / ARMv7; raw CPU identification is not included in available excerpts | C-01 |
| Exact retail model / SoC | **Unknown from current device logs** | — |
| Chromium renderer sandbox enabled? | **Unknown** | U-01 |
| Chromium process UID, privileges, seccomp, namespaces | **Unknown** | U-01 |
| Native code execution on this TV | **Not demonstrated in supplied logs** | — |
| Linux root access on this TV | **Not demonstrated in supplied logs** | — |
| Public exploit verified to work on this exact combination | **None established** | C-02 |

## 2. Primary evidence: outputs actually shared

### E-01 — Component versions returned by the TV API

**Source:** Pasted JSON output in the earlier project chat titled *Summarize Vizio ACR findings*, dated 2026-10-19. The exact API request path and command invocation were not preserved in the available excerpt.

**Observed response fields (faithful subset of shared output):**

```json
{
  "status": {
    "RESULT": "SUCCESS",
    "DETAIL": "Success"
  },
  "keys": ["ITEM", "STATUS", "URI"],
  "components": [
    {"name": "FIRMWARE", "value": "3.720.9.1-1"},
    {"name": "SCPL", "value": "3.4.3-2614.0002"},
    {"name": "acr", "value": "3.5.1106"},
    {"name": "firmware", "value": "3.720.9.1-1"},
    {"name": "scpl", "value": "3.4.3-2614.0002"}
  ]
}
```

**Findings:**

- Firmware identifier `3.720.9.1-1` was returned in both uppercase and lowercase component names.
- SCPL identifier `3.4.3-2614.0002` was returned in both uppercase and lowercase component names.
- ACR component identifier `3.5.1106` was returned.
- The response itself indicated `RESULT: SUCCESS`.

**Limitations:** The excerpt also begins a `vizios` component whose value is truncated (`mtk...`). Its complete value is unavailable, so no SoC model, platform identifier, or VIZIO OS version can be established from that field here. The excerpt does not preserve the exact endpoint, authentication mode, or full response.

### E-02 — Invalid POST to the SCPL installer path

**Source:** This conversation. The user ran a test after receiving the following recommended command (with the actual TV address substituted):

```bash
curl -ksS -i --max-time 8 \
  -X POST \
  --data 'data=123' \
  'https://TV_IP:7345/install'
```

**Exact response pasted by the user:**

```http
HTTP/2 500
content-type: text/html
content-length: 218
date: Tue, 20 Oct 2026 02:26:19 GMT
server: lighttpd/1.4.67

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Unhandled Exception</title>
</head><body>
<h1>Unhandled Exception</h1>
<p>An unhandled exception was thrown by the application.</p>
</body></html>
```

**Findings:**

- An HTTPS service was reachable on the TV's port `7345` at the time of this request.
- The response used `HTTP/2` and reported `lighttpd/1.4.67` as the server.
- The `/install` request with the above intentionally invalid POST data returned HTTP `500` and an application exception page.
- This response **does not demonstrate** command injection, successful installation, file upload, native execution, or root access.

**What the response cannot distinguish:** An absent route, a registered handler that throws on malformed input, a rejected request shape, filtering, and other server-side failures might produce similar errors. The response alone **cannot establish whether CVE-2021-27944 is present or patched**.

**Time note:** The time above is the server-supplied `Date` header (UTC), not an independently recorded client timestamp.

### E-03 — Local inspection excerpt from an x64 V8 proof-of-concept

**Source:** Earlier project chat *Investigate Root Debugging Entry Points*, dated 2026-10-19. The available excerpt contains line-numbered matches from an exploit file, including:

```text
42://"C:\v8\v8\out\x64.release\d8.exe" --allow-natives-syntax exploit.js
44:const FIXED_ARRAY_HEADER_SIZE = 8n;
46:var arr_buf = new ArrayBuffer(8);
70:function gc_major() { //mark-sweep
100:    //%DebugPrint(Reflect.getOwnPropertyDescriptor(globalThis, "stack"));
```

**Findings:**

- The inspected code included an example invocation referencing `x64.release/d8.exe` and V8 native/debugging syntax.
- The snippet is **not** evidence that this code executed on the Vizio, nor that it is portable to ARMv7.
- No output demonstrating a V8 vulnerability trigger, arbitrary native execution, or privilege change on this TV is available in these excerpts.

## 3. Earlier investigation claims without preserved raw device logs

These items appeared in earlier project-chat summaries or discussion. They are included to avoid losing context, **not** to upgrade them into verified findings.

| ID | Prior statement or lead | Evidentiary status on this TV |
| --- | --- | --- |
| C-01 | Chromium `108` and CPU architecture ARMv7 / 32-bit ARM | Reported earlier; version/CPU-identification output not currently available |
| C-02 | No confirmed ready-to-run exploit for this exact Chromium 108 + ARMv7 + firmware combination | Research assessment, not proof that no exploit exists |
| C-03 | WebP / CVE-2023-4863 testing was inconclusive | Earlier summary; detailed test inputs and device logs absent |
| C-04 | USB-based routes were considered but not validated | Earlier discussion; exact USB experiments and logs absent |
| C-05 | CVE-2023-2033 public proof-of-concept had x86-64 / `d8` assumptions | Partially supported by E-03; not a target-device result |
| C-06 | CVE-2023-1214 was proposed as a V8 research candidate | No successful device reproduction captured |
| C-07 | CVE-2023-6702 was proposed as a V8 research candidate | No successful device reproduction or ARMv7 port captured |
| C-08 | A newer SmartCast research repository demonstrated a webview-to-internal-API path | External-only; different device, Chromium, and SCPL versions |
| C-09 | UART hardware research exists for a TV reportedly using firmware `3.720.9.1-1` | External-only; does not establish this particular TV's retail model, UART state, or boot restrictions |

### Important separation: other devices

A public October 2026 write-up for an **onn. 65S4V4 / W4K65M-1030** described VIZIO OS `1.8.1767.1`, SCPL `3.7.3-2640`, Chromium `128.0.6613.194`, and a MediaTek MT5586. Its author reported paired remote webview JavaScript execution and internal configuration writes, **not kernel/root execution**. This research **must not be conflated with** this TV's observed firmware `3.720.9.1-1` and SCPL `3.4.3-2614.0002`.

Reference: <https://github.com/vindeckyy/smartcast-backdoor> (external research; no reproduction on this device).

Other earlier discussions referenced a Vizio VFD40M-0810 hardware report associated with the same firmware string. A matching version string alone does **not** prove that the user's TV has that exact model, SoC, boot configuration, or serial-console restrictions.

## 4. Requests suggested but without returned results

The earlier assistant suggested comparing:

```bash
curl -ksS --http1.1 -i "https://TV_IP:7345/install"
curl -ksS --http1.1 -i "https://TV_IP:7345/this-route-does-not-exist-12345"
```

**No user response to either command appears in the available conversation.** These are planned/mentioned checks, not completed findings. Do not infer what either returned.

## 5. Unresolved technical questions

### U-01 — Chromium sandbox and effective privileges

**Current status: unknown.** No process command line, `Seccomp` field, namespace map, process UID/GID, container policy, or renderer process tree has been shared.

A stock Chromium 108 Linux build's usual behavior is not sufficient to prove the same behavior on this embedded Vizio build. In particular, the available evidence does **not** establish whether `--no-sandbox` is used, whether a renderer is isolated, or what effective privileges would be available following renderer code execution.

### U-02 — Exact hardware and browser build identity

An untruncated device identification response, CPU details, and browser version/build output are not included in the available raw logs. The reported ARMv7 and Chromium 108 versions remain useful leads but are not independently documented here.

### U-03 — SCPL `/install` handler behavior

Only one malformed POST response (E-02) is recorded here. It is insufficient to distinguish an unavailable endpoint from one that errors on the supplied input. No successful sideload, command execution, or root result has been shown.

### U-04 — Root-access path

No demonstrated renderer exploit, sandbox escape, privileged service exploit, working UART shell, or elevated `id`/`whoami` output appears in the available logs. Therefore the overall chain to Linux root remains **unproven**.

## 6. Evidence required before stronger claims can be made

The following are evidence types, not a request to repeat earlier unproductive exploit tests:

1. **For Chromium version/architecture:** a full browser user-agent or build/version readout and a device CPU identification response.
2. **For sandbox status:** firmware-backed launch configuration or read-only process diagnostics showing renderer command-line flags, UID/GID, seccomp, and namespace isolation.
3. **For root claims:** an authenticated capture of privilege identity and execution context on the specific TV, with a documented way that access was obtained.
4. **For installer conclusions:** differentiated handler responses or relevant firmware implementation evidence, rather than treating a generic `500` as proof of either vulnerability or patching.
5. **For future records:** retain exact commands, output, timestamps/time zone, model, source device, test conditions, and hashes for any copied binaries or firmware files. Remove secrets such as pairing tokens, passwords, device serials, MAC addresses, and IP addresses from shared reports when not necessary.

## 7. Findings register and update rules

| Finding | Confidence | Conclusion |
| --- | --- | --- |
| F-001 | High — pasted API output | Firmware reported as `3.720.9.1-1` |
| F-002 | High — pasted API output | SCPL reported as `3.4.3-2614.0002` |
| F-003 | High — pasted API output | ACR component reported as `3.5.1106` |
| F-004 | High — pasted HTTP response | Port 7345 responded over HTTPS with HTTP/2 and `lighttpd/1.4.67` |
| F-005 | High — pasted HTTP response | Invalid `/install` POST returned `500 Unhandled Exception` |
| F-006 | High — pasted exploit-file excerpt | Examined V8 sample referenced an x64 `d8` development build |
| F-007 | Not established | Chromium sandbox status on this firmware |
| F-008 | Not established | Native Linux execution and root privileges on this TV |

**Update policy:** Append new evidence under a new `E-##` entry; do not rewrite an earlier uncertainty as established without the corresponding raw result. Label any material reproduced on a separate device **External-only**. If later logs contradict a finding, preserve both observations and note different firmware, dates, or test conditions.

---

*Compiled from the currently visible project-chat excerpts and this conversation on 2026-10-19. No firmware image, device log archive, or complete previous-chat export was available to validate additional assertions.*
