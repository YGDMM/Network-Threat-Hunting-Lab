# INCIDENT REPORT – THREAT HUNTING LAB

⸻

## 1. EXECUTIVE SUMMARY

This investigation identifies a multi-stage suspicious network interaction targeting the host 10.1.17.215 (DESKTOP-L8C5GSJ) within a Windows Active Directory environment.

The activity shows a clear progression from early external communication toward coordinated multi-node external infrastructure behaviour. Evidence suggests:

* Possible phishing or fake authentication entry point
* Subsequent staged external communication bursts
* Sustained multi-host external connectivity patterns
* Behaviour consistent with post-compromise or automated beaconing activity

No malware binary was directly observed; all conclusions are based on network telemetry and behavioural correlation.

⸻

## 2. VICTIM PROFILE

| Field | Value |
|------|------|
| User | shutchenson |
| Hostname | DESKTOP-L8C5GSJ |
| Domain | BLUEMOONTUESDAY.COM |
| AD Environment | BLUEMOONTUESDAY |
| Kerberos Activity | Yes |
| Domain Controller | 10.1.17.2 (WIN-GSH54QLW48D) |
| Gateway | 10.1.17.1 |
| LAN Range | 10.1.17.0/24 |
| Authentication Domain | BLUEMOONTUESDAY.COM |
| Evidence Source | Kerberos ticket requests observed during lateral movement analysis |
| Victim IP | 10.1.17.215 |
| Victim MAC | 00:d0:b7:26:4a:74 |
| First seen | 2025-01-22 20:44:56.530137+01:00 |
| Last seen | 2025-01-22 21:38:18.918250+01:00 |
| Top Protocols | TCP 26741, TLSv1.2 3642, TLSv1.3 3403, DNS 1512, HTTP 1253, LDAP 497, QUIC 450, ARP 340, DRSUAPI 292, SMB2 252 |
| Detected Hostnames | _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.bluemoontuesday.com; win-gsh54qlw48d.bluemoontuesday.com; DESKTOP-L8C5GSJ.bluemoontuesday.com; bluemoontuesday.com; wpad.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.WIN-GSH54QLW48D.bluemoontuesday.com; _ldap._tcp.WIN-GSH54QLW48D.bluemoontuesday.com; _kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.bluemoontuesday.com; WIN-GSH54QLW48D.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones.bluemoontuesday.com |
| Domain-related Activity | _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.bluemoontuesday.com; win-gsh54qlw48d.bluemoontuesday.com; DESKTOP-L8C5GSJ.bluemoontuesday.com; bluemoontuesday.com; wpad.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.WIN-GSH54QLW48D.bluemoontuesday.com; _ldap._tcp.WIN-GSH54QLW48D.bluemoontuesday.com; _kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.bluemoontuesday.com; WIN-GSH54QLW48D.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones.bluemoontuesday.com; _ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones.bluemoontuesday.com |
  
Key Observations

* Strong Active Directory integration (Kerberos, LDAP, SMB2, DRSUAPI)
* High internal authentication activity
* Simultaneous external communication during peak phases

## 3. INITIAL COMPROMISE VECTOR

Initial suspicious activity is associated with:

* Domain: authenticatoor.org
* IP: 82.221.136.26
* Evidence: TLS SNI inspection

Interpretation

This pattern is consistent with:

* Fake authentication / software download infrastructure
* Possible phishing or staged initial access mechanism
* Early compromise or user-triggered external connection

## 4. SUSPICIOUS EXTERNAL INFRASTRUCTURE

| Type | IOC | Evidence | Category | Confidence |
|------|-----|----------|----------|------------|
| Domain | authenticatoor.org | TLS SNI observed during initial compromise window | Suspicious authentication phishing / staging domain | High |
| IP | 82.221.136.26 | TLS SNI correlation with fake authentication domain | Suspicious hosting / staging infrastructure | High |
| IP | 5.252.153.241 | High-volume bootstrap traffic during initial peak phase | Suspicious external host (bootstrap activity) | Medium-High |
| IP | 45.125.66.32 | Sustained peak traffic and coordinated communication pattern | Suspicious external infrastructure node (primary) | Medium |
| IP | 45.125.66.252 | Secondary sustained communication pattern | Suspicious external infrastructure node (secondary) | Medium |
| IP | 23.55.125.176 | High-volume TLS traffic consistent with CDN delivery (Akamai) | CDN infrastructure (likely benign noise) | Low (contextual) |
| ASN | AS133398 | HostBaltic infrastructure hosting 45.125.66.0/24 range | Hosting provider correlation | Medium |
| Domain | bluemoontuesday.com | Identified as internal AD domain traffic | Internal infrastructure (non-malicious) | High |

Notes

Roles are inferred using:

* Temporal correlation
* Traffic bursts
* Session persistence
* TLS SNI association
* WHOIS / ASN context


## 5. BEHAVIOURAL ANALYSIS

Observed behaviour includes:

* DNS spikes (e.g. ping3.dyngate.com)
* Peak traffic bursts (>6000 packets/min)
* Mixed TLS, HTTP, and DNS activity
* Strong internal AD traffic coexistence
* Non-periodic communication patterns (jitter present)

Key Insight

Traffic does not show strict beaconing, but instead:

* irregular bursts
* clustered communication windows
* multi-node coordination patterns

## 6. IOC TIMELINE (CORE RECONSTRUCTION)

| Timestamp | Event Type | Source | Destination | Details | Confidence |
|------------|------------|--------|-------------|----------|------------|
| 2025-01-22 20:45:36 | INITIAL_COMPROMISE_INDICATOR | 10.1.17.215 | 82.221.136.26 | TLS SNI -> authenticatoor.org | High |
| 2025-01-22 20:47:00 | BOOTSTRAP_ACTIVITY | 10.1.17.215 | 5.252.153.241 | Initial burst (>5600 packets / 30s) | High |
| 2025-01-22 20:59:30 | C2_STAGE_START | 10.1.17.215 | 45.125.66.32 | First major activity spike | Medium |
| 2025-01-22 21:00:00 | SECONDARY_NODE_START | 10.1.17.215 | 45.125.66.252 | Secondary TLS communications begin | Medium |
| 2025-01-22 21:25:00 | COORDINATED_ACTIVITY | C2_CLUSTER | Victim Host | Multi-node synchronization detected | Medium |

## 7. ENRICHMENT DATA

WHOIS / ASN Findings

* AS133398 (HostBaltic) → 45.125.66.32 / 45.125.66.252
* AS205775 (Neon Core) → 5.252.153.241
* AS50613 (Advania Iceland) → 82.221.136.26
* AS16625 (Akamai CDN) → 23.55.125.176 (likely benign noise)

Interpretation

* Infrastructure distributed across multiple hosting providers
* No corporate ownership signals detected
* Strong indication of rented / disposable infrastructure

## 8. IOC TABLE SUMMARY

Confirmed Suspicious Indicators

* authenticatoor.org (phishing/staging domain)
* 82.221.136.26 (initial access node)
* 5.252.153.241 (bootstrap activity)
* 45.125.66.32 (primary node)
* 45.125.66.252 (secondary node)

Internal Context

* bluemoontuesday.com → Active Directory domain
* Kerberos + LDAP confirms domain-integrated environment

## 9. CORRELATED FINDINGS (KEY INSIGHT)

The combination of:

* TLS SNI indicators
* burst-based traffic spikes
* multi-node external communication
* hosting-provider dispersion
* AD internal coexistence

suggests:

A staged multi-phase network interaction involving external infrastructure coordination rather than isolated anomalous connections.

## 10. ATTACK RECONSTRUCTION

The observed network activity begins with early-stage outbound communication from the host 10.1.17.215 toward 82.221.136.26, where TLS SNI inspection reveals a connection to the domain authenticatoor.org.

This interaction represents the earliest identifiable indicator of suspicious external communication and may correspond to an initial staging or phishing-related contact.

Shortly after, a significant outbound traffic spike is observed toward 5.252.153.241, indicating a transition from passive exposure to active external communication and likely bootstrap activity.

The communication pattern then evolves into sustained interactions with multiple external IPs, including 45.125.66.32 and 45.125.66.252, which exhibit coordinated behaviour across defined temporal windows.

Temporal correlation analysis shows clustered activity phases with overlapping peaks, consistent with jittered communication patterns commonly associated with evasive infrastructure.

DNS and TLS SNI data provide partial attribution, with TLS SNI being the most reliable external indicator. DNS is partially mediated by internal resolution mechanisms, limiting external attribution fidelity.

When combined with WHOIS, ASN data, and traffic behaviour, the evidence strongly suggests:

* Multi-stage external communication chain
* Coordinated infrastructure usage
* Post-compromise or automated communication behaviour

However:

No definitive malware execution or confirmed C2 channel is established — classification remains suspicious infrastructure with C2-like indicators.


## FINAL CONCLUSION

This investigation identifies a multi-stage suspicious network interaction involving:

* Early external compromise indicators
* Bootstrap communication phase
* Multi-node coordinated external infrastructure
* Sustained post-compromise communication patterns

## Final Classification

Suspicious infrastructure with C2-like behavioural indicators (not fully confirmed command-and-control)
