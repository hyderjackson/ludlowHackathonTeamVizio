# ludlowHackathonTeamVizio

Vizio SmartCast ACR investigation for the Smart TV ACR Hackathon.

## Layout

- `Wireshark Captures/Vizio/CSVs/` tshark exports, split by ACR on/off.
- `Wireshark Captures/Vizio/WhoIsResults/` RDAP/whois lookups for the IPs seen.
- `Scripts/` analysis scripts:
  - `PacketTracerIPWhoIs.py` runs RDAP whois over the IPs in a capture CSV.
  - `acrpipe.py` parses a pcap into per-run summaries (flows, DNS, SNI, ACR indicators).
- `Findings/` write-up and run metadata:
  - `FINDINGS.md` the findings.
  - `runs-metadata.md` metadata for each capture run.
