# Measurement hooks

These are copies of the lightweight hooks used in the experiment, adapted to require `ACR_EVENT_DIR` for private output. `fingerprint_events.py` records request/response events without bodies or URLs. `certificate_events.py` records connection ordinals, certificate digests and categorized SNI status, plus safe counters.

They do not create interception rules, start a proxy, install a CA, choose a TV, or provide the necessary outer traffic scope. The path filter alone is not a TV/destination filter. A separate reviewed interception setup must scope the traffic correctly. Do not deploy the addon against an unrelated shared proxy merely to try it.

The certificate hook expects private `expected-peer.json` and `certificate-controls.json` files and a configured test leaf. No keys or sample private configs are included. The public-certificate hook records what the proxy selected locally; it does not independently prove every resumed TLS handshake on the wire.
