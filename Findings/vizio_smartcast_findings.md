# VIZIO SmartCast / VIZIO OS — Technical Findings

**Record updated:** 2026-10-20  
**Target:** VIZIO SmartCast television running firmware `3.720.9.1-1`  
**Status:** Investigation ongoing; Linux root access not demonstrated

## 1. Scope and evidence conventions

This record documents device observations, reproduced response excerpts, and technical leads relevant to SmartCast service exposure, Chromium execution, and Linux privilege boundaries. Results from other devices are clearly distinguished from results observed on the target.

Evidence classifications:

- **Observed:** A command result, protocol response, or file excerpt has been retained below.
- **Reported:** A prior technical result has been noted, but its supporting raw output has not been retained in this evidence set.
- **External:** Published work on a different device or build; not reproduced on the target.
- **Unknown:** No evidence sufficient to establish the property.

A missing exploit result does not prove a vulnerability is absent or patched. Generic error responses are not treated as evidence of either exploitability or remediation.

## 2. Device component identification — E-001

**Evidence type:** Observed API response  
**Request path:** Not retained  
**Recorded date:** 2026-10-19

The following relevant fields were returned in a successful component query:

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

This is a **selected excerpt**, not the complete API response. Firmware and SCPL versions each appear under uppercase and lowercase component names. The ACR component reports `3.5.1106`. The response indicates `RESULT: SUCCESS`.

An additional `vizios` component was present but its value is truncated (`mtk...`) in the retained extract. That field does not establish an exact processor or platform identifier. The complete endpoint invocation, authentication method, and model identification were not preserved.

## 3. SCPL `/install` request — E-002

**Evidence type:** Observed HTTP response  
**Endpoint:** `https://<TV_IP>:7345/install`  
**Request:** Intentionally invalid POST body; no executable payload

Associated test-command template:

```bash
curl -ksS -i --max-time 8 \
  -X POST \
  --data 'data=123' \
  'https://TV_IP:7345/install'
```

The exact substituted IP address and complete local command invocation were not retained. The recorded response was:

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

**Established:**

- An HTTPS service responded on TCP port `7345`.
- The recorded response used HTTP/2 and identified `lighttpd/1.4.67`.
- The malformed `/install` POST returned HTTP `500` and an `Unhandled Exception` page.

**Not established:** Whether the endpoint is registered, rejects this request format, invokes an exception-prone handler, or is blocked by server-side controls. This result alone does not establish that the historical ViziOwn/CVE-2021-27944 command-injection issue is exploitable, mitigated, or patched. No file installation, command execution, or privilege escalation was observed in the retained response.

**Timestamp note:** `20 Oct 2026 02:26:19 GMT` is the server-provided HTTP `Date` header, not an independently captured client clock.

## 4. V8 proof-of-concept compatibility review — E-003

**Evidence type:** Observed source-file excerpt  
**Recorded date:** 2026-10-19  
**Target execution:** Not demonstrated

Selected line-numbered matches from an inspected V8 exploit file:

```text
42://"C:\v8\v8\out\x64.release\d8.exe" --allow-natives-syntax exploit.js
44:const FIXED_ARRAY_HEADER_SIZE = 8n;
46:var arr_buf = new ArrayBuffer(8);
70:function gc_major() { //mark-sweep
100:    //%DebugPrint(Reflect.getOwnPropertyDescriptor(globalThis, "stack"));
```

The file includes an invocation for an x64 V8 `d8` development binary with native syntax enabled. The retained excerpt does not establish compatibility with ARMv7, execution inside the television's production Chromium build, a successful memory-corruption trigger, or Linux privilege escalation.

## 5. Platform and Chromium facts requiring corroboration — C-001

| Property | Status | Evidence limit |
| --- | --- | --- |
| Firmware `3.720.9.1-1` | **Observed** | E-001 |
| SCPL `3.4.3-2614.0002` | **Observed** | E-001 |
| ACR `3.5.1106` | **Observed** | E-001 |
| HTTP/2 service on port `7345`, lighttpd `1.4.67` | **Observed** | E-002 |
| Chromium `108` | **Reported** | Full user-agent or build output not retained |
| 32-bit ARM / ARMv7 | **Reported** | Raw CPU or ABI identification not retained |
| Retail model and exact SoC | **Unknown** | No complete model/processor response retained |
| Chromium sandbox enabled or disabled | **Unknown** | No launch flags or process-level evidence retained |
| Renderer UID/GID, seccomp, namespaces | **Unknown** | No process diagnostic capture retained |
| Native execution on target | **Not demonstrated** | No successful native-execution trace retained |
| Linux root on target | **Not demonstrated** | No elevated identity or shell trace retained |

Chromium's default Linux sandbox behavior cannot establish the effective sandbox configuration of this embedded browser. Required evidence includes process command lines, UID/GID, seccomp state, and namespace isolation, or the equivalent facts from the firmware's launch configuration.

## 6. Exploit research and prior leads — C-002

The following items are research leads or prior assessments, **not verified vulnerabilities on the target**:

| Lead | Current evidence boundary |
| --- | --- |
| CVE-2021-27944 / ViziOwn `/install` | Historical SmartCast exploit; E-002 does not reproduce its command-execution behavior |
| CVE-2023-4863 / WebP | Earlier testing reported as inconclusive; raw device test output not retained |
| CVE-2023-1214 / V8 | Candidate requiring exact-version and architecture validation; no successful target reproduction retained |
| CVE-2023-2033 / V8 | Examined proof-of-concept includes x64 `d8` assumptions (E-003); no ARMv7 target execution retained |
| CVE-2023-6702 / V8 | Public renderer-execution research exists; no verified ARMv7 port or target reproduction retained |
| USB entry points | No verified entry point or successful target outcome retained |
| UART / hardware console | No target-specific boot transcript, authenticated shell, or privilege result retained |

### External research: newer SmartCast implementation

A public October 2026 report covers **onn. 65S4V4 / W4K65M-1030**, VIZIO OS `1.8.1767.1`, SCPL `3.7.3-2640`, Chromium `128.0.6613.194`, and MediaTek MT5586. The report describes paired control-API access leading to JavaScript execution in a system webview and persistent configuration-store changes. It explicitly does **not** demonstrate Linux kernel or root access.

Reference: <https://github.com/vindeckyy/smartcast-backdoor>

**Applicability:** External only. The tested hardware, Chromium version, and SCPL build differ from E-001 and the reported target environment. The report's successful results must not be attributed to this television.

### External research: hardware and UART

A separate Vizio VFD40M-0810 hardware-research report has been associated with firmware version `3.720.9.1-1`. The shared firmware string does not independently establish the target television's retail model, SoC, bootloader configuration, serial console access, or filesystem protections. No matching on-device boot log has been retained in this evidence set.

## 7. Checks without recorded results — C-003

The following comparison commands were identified but have **no retained response**:

```bash
curl -ksS --http1.1 -i "https://TV_IP:7345/install"
curl -ksS --http1.1 -i "https://TV_IP:7345/this-route-does-not-exist-12345"
```

These are **uncompleted or undocumented checks**, not evidence of endpoint behavior. No result should be inferred.

## 8. Open technical questions

1. **Exact browser and architecture:** Confirm Chromium build identity and CPU/ABI from full primary-source output.
2. **Renderer isolation:** Determine the actual Chromium process launch flags, effective UID/GID, namespace configuration, and seccomp restrictions for firmware `3.720.9.1-1`.
3. **SCPL installer semantics:** Establish whether `/install` is registered and what its actual implementation accepts. The HTTP 500 response in E-002 cannot answer this.
4. **Native execution boundary:** Determine whether any reproducible primitive yields native execution, and under which process privileges.
5. **Linux privilege escalation:** No validated path from the exposed application/browser surface to Linux root has been recorded.

## 9. Evidence collection and contribution format

For additional findings contributed to the repository, include:

- **ID and title:** Unique identifier (for example, `E-004 — <short title>`).
- **Environment:** Device model, firmware, SCPL/browser version, and relevant build details.
- **Method:** Exact command or request with secrets and private identifiers redacted.
- **Raw output:** Unmodified relevant response, log, or file excerpt.
- **Timestamp:** Date, time, timezone, and whether the time came from a server or client.
- **Interpretation:** Separate directly established behavior from hypotheses and missing evidence.
- **Source:** Local artifact path, commit reference, capture hash, or external URL when available.

Preserve contradictory observations with their firmware versions, dates, and test conditions rather than overwriting earlier records. Remove authentication tokens, serial numbers, MAC addresses, and unnecessary IP addresses from public submissions.

## 10. Current conclusion

The retained primary evidence establishes firmware `3.720.9.1-1`, SCPL `3.4.3-2614.0002`, ACR `3.5.1106`, an HTTPS service on port `7345`, and an HTTP `500 Unhandled Exception` response to one invalid `/install` POST. An inspected V8 proof-of-concept references an x64 development runtime but has no demonstrated execution on the target.

**Chromium sandbox status, effective renderer privileges, ARMv7 exploit compatibility, native execution, and Linux root access remain unverified.** External demonstrations on other SmartCast devices do not close those evidence gaps.
