# Threat Hunting Lab – PCAP Behavioral Analysis

## Overview

This project is a full end-to-end threat hunting investigation based on a real PCAP file.  
The objective is to identify suspicious network behaviour, reconstruct a potential intrusion chain, and extract meaningful Indicators of Compromise (IOCs).

The analysis follows a structured DFIR-style methodology combining:

- Packet-level inspection (TShark)
- DNS & TLS correlation
- Temporal peak analysis
- Infrastructure profiling (WHOIS / ASN)
- Behavioral traffic analysis

---

## Methodology

The investigation is structured into multiple phases:

1. Baseline traffic extraction (PCAP → TSV)
2. DNS analysis
3. Protocol and lateral movement review
4. Timeline reconstruction
5. Peak activity detection
6. IOC correlation across time windows
7. Infrastructure enrichment (WHOIS / ASN)
8. Victim profiling
9. IOC synthesis
10. Attack reconstruction narrative

---

## Key Findings

### Initial Access Vector
- Suspicious domain observed via TLS SNI:
  - `authenticatoor.org`
- Behaviour consistent with phishing-style authentication lure

---

### External Infrastructure Observed

Multiple external IPs show coordinated or staged communication patterns:

- `82.221.136.26` → staging / phishing-linked host
- `5.252.153.241` → initial burst activity (bootstrap phase)
- `45.125.66.32` → sustained communication node
- `45.125.66.252` → secondary infrastructure node
- `23.55.125.176` → high-volume CDN infrastructure (Akamai, likely benign)

---

### Temporal Behaviour

Traffic analysis reveals structured phases:

- Initial contact phase (20:45)
- Burst activity phase (20:47)
- Infrastructure engagement (20:59–21:00)
- Coordinated multi-node communication (21:25+)
- Sustained low-volume activity (post-21:30)

---

### Behavioural Characteristics

- TLS (v1.2 / v1.3) dominates external communication
- Irregular beacon-like timing (jittered behaviour)
- High packet bursts in short time windows
- Internal AD traffic coexists with external communication
- DNS partially internally resolved (limited external visibility)

---

## IOC Summary

| Type   | Indicator | Description |
|--------|-----------|-------------|
| Domain | authenticatoor.org | Suspicious phishing/staging domain |
| IP     | 82.221.136.26 | TLS SNI correlated staging host |
| IP     | 5.252.153.241 | Initial burst infrastructure |
| IP     | 45.125.66.32 | Primary suspicious node |
| IP     | 45.125.66.252 | Secondary node |
| IP     | 23.55.125.176 | CDN (Akamai) high-volume benign traffic |
| ASN    | AS133398 | HostBaltic infrastructure |

---

## Conclusion

The observed network behaviour is consistent with a multi-stage suspicious infrastructure communication pattern involving staged external hosts and coordinated traffic peaks.

While no direct malware payload was identified, the combination of:

- TLS SNI analysis
- Traffic burst behaviour
- Temporal clustering
- Infrastructure correlation

supports a **suspicious post-compromise communication scenario with C2-like behaviour indicators**.

However, classification remains at **“suspicious infrastructure interaction” rather than confirmed command-and-control compromise**.

---

## Tools Used

- TShark
- Python (Pandas)
- WHOIS lookup
- ipinfo ASN enrichment
- TLS / DNS correlation analysis


---

## Author Notes

This project focuses on behavioural detection and infrastructure correlation rather than signature-based malware detection.rently under active development.
