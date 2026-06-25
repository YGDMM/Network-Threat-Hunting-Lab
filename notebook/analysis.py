# %% PHASE 1 - LOAD PCAP FILE (TShark + Pandas)

import subprocess
import pandas as pd

pcap_path = "/x/"
output_file = "/x.tsv/"

cmd = [
    "tshark",
    "-r", pcap_path,
    "-T", "fields",

    "-e", "frame.number",
    "-e", "frame.time",
    "-e", "eth.src",
    "-e", "eth.dst",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "_ws.col.Protocol",
    "-e", "frame.len",

    "-e", "udp.port",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "tcp.stream",
    "-e", "tcp.flags",
    "-e", "tcp.flags.syn",
    "-e", "tcp.flags.reset",
    "-e", "tcp.flags.fin",
    "-e", "tcp.flags.str",

    "-E", "header=y",
    "-E", "separator=\t",
    "-E", "quote=d",
    "-E", "occurrence=f",
    "-E", "aggregator=,"
]

with open(output_file, "w") as f:
    subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)

df = pd.read_csv(output_file, sep="\t")


# %% PHASE 2 - BASELINE TRAFFIC ANALYSIS


print(df["_ws.col.protocol"].value_counts().head(15))
print(df["ip.src"].value_counts().head(10))
print(df["ip.dst"].value_counts().head(10))

largest_packets = df.sort_values(by="frame.len", ascending=False)[
    ["frame.number", "ip.src", "ip.dst", "_ws.col.protocol", "frame.len"]
]

print(largest_packets.head(10))


# %% PHASE 3 - DNS ANALYSIS


from pathlib import Path

pcap_path = "/x.pcap/"
dns_output = "/x.csv/"

if not Path(pcap_path).exists():
    raise FileNotFoundError("PCAP file not found")

cmd = [
    "tshark",
    "-r", pcap_path,
    "-Y", "dns",
    "-T", "fields",
    "-E", "separator=|",
    "-E", "header=y",
    "-e", "frame.number",
    "-e", "frame.time",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "dns.qry.name"
]

with open(dns_output, "w") as f:
    subprocess.run(cmd, stdout=f)

df_dns = pd.read_csv(dns_output, sep="|")

print(df_dns.head(20))

print(df_dns["ip.src"].value_counts().head(10))
print(df_dns["dns.qry.name"].value_counts().head(20))


# %% PHASE 3.1 - ADVANCED DNS ANALYSIS


print("\nTOP 20 DNS QUERIES\n")

print(
    df_dns["dns.qry.name"]
    .dropna()
    .value_counts()
    .head(20)
)

print("\nSUSPICIOUS DNS PATTERNS\n")

patterns = "dyngate|duckdns|no-ip|dynu|hopto|login|secure|update"

suspicious_dns = df_dns[
    df_dns["dns.qry.name"]
    .fillna("")
    .str.contains(patterns, case=False)
]

print(
    suspicious_dns[
        ["frame.number", "ip.src", "dns.qry.name"]
    ].head(30)
)

print("\nTOP DNS SOURCES\n")

print(
    df_dns["ip.src"]
    .value_counts()
    .head(20)
)

print("\nTOP DNS QUERIES DISTRIBUTION\n")

print(
    df_dns["dns.qry.name"]
    .value_counts()
)


# %% PHASE 4 - LATERAL MOVEMENT ANALYSIS


import subprocess
import pandas as pd
from pathlib import Path

pcap_path = "/.pcap/"
output_csv = "/.csv/"

cmd = [
    "tshark",
    "-r", pcap_path,
    "-Y", "ldap || smb || kerberos || ntlmssp || dcerpc",
    "-T", "fields",
    "-E", "separator=|",
    "-E", "header=y",

    "-e", "frame.number",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "_ws.col.protocol",
    "-e", "frame.len",

    "-e", "kerberos.CNameString",
    "-e", "kerberos.realm",
    "-e", "kerberos.SNameString",

    "-e", "ntlmssp.auth.username",
    "-e", "ntlmssp.auth.domain",
    "-e", "ntlmssp.auth.hostname"
]

with open(output_csv, "w") as f:
    subprocess.run(cmd, stdout=f)

df_lm = pd.read_csv(output_csv, sep="|")


# %% PHASE 4.1 - LATERAL MOVEMENT PROTOCOL ANALYSIS


print("\nKERBEROS TRAFFIC\n")

if "_ws.col.protocol" in df_lm.columns:
    krb = df_lm[df_lm["_ws.col.protocol"] == "KRB5"]
    print(krb[["frame.number", "ip.src", "ip.dst", "frame.len"]].head(20))

print("\nSMB TRAFFIC\n")

smb = df_lm[
    df_lm["_ws.col.protocol"]
    .astype(str)
    .str.contains("SMB", na=False)
]

print(
    smb[["ip.src", "ip.dst", "_ws.col.protocol", "frame.len"]]
    .head(20)
)


# %% PHASE 4.2 - LATERAL MOVEMENT ENUMERATION


print("\nDOMAIN DISCOVERY\n")

possible_domains = []

for col in df_lm.columns:
    if df_lm[col].dtype == object:
        values = df_lm[col].dropna().astype(str)

        domain_hits = values[
            values.str.contains("bluemoontuesday", case=False, na=False)
        ]

        possible_domains.extend(domain_hits.tolist())

print(pd.Series(possible_domains).value_counts().head(20))


print("\nLDAP DESTINATIONS\n")

ldap = df_lm[
    df_lm["_ws.col.protocol"]
    .astype(str)
    .str.contains("LDAP", na=False)
]

print(ldap["ip.dst"].value_counts().head(10))


print("\nINTERNAL NETWORK RANGE\n")

internal_ips = pd.concat([df_lm["ip.src"], df_lm["ip.dst"]])
internal_ips = internal_ips[internal_ips.astype(str).str.startswith("10.")]

print(sorted(internal_ips.dropna().unique()))


print("\nHOSTNAME DISCOVERY\n")

hostname_candidates = []

for col in df_lm.columns:
    if df_lm[col].dtype == object:
        values = df_lm[col].dropna().astype(str)

        hosts = values[
            values.str.contains("DESKTOP|WIN-", case=False, na=False)
        ]

        hostname_candidates.extend(hosts.tolist())

print(pd.Series(hostname_candidates).value_counts().head(20))


print("\nKERBEROS USERS\n")

if "kerberos.CNameString" in df_lm.columns:
    print(df_lm["kerberos.CNameString"].dropna().value_counts().head(20))


print("\nNTLM USERS\n")

if "ntlmssp.auth.username" in df_lm.columns:
    print(df_lm["ntlmssp.auth.username"].dropna().value_counts().head(20))


print("\nNTLM HOSTNAMES\n")

if "ntlmssp.auth.hostname" in df_lm.columns:
    print(df_lm["ntlmssp.auth.hostname"].dropna().value_counts().head(20))


# %% PHASE 5 - TIMELINE ANALYSIS


import pandas as pd
import matplotlib.pyplot as plt

pcap_tsv_path = "/x.tsv/"
output_plot_path = "/x.png/"

df_time = pd.read_csv(pcap_tsv_path, sep="\t")

df_time["frame.time"] = pd.to_datetime(
    df_time["frame.time"],
    format="%b %d, %Y %H:%M:%S.%f %Z",
    errors="coerce"
)

df_time = df_time.dropna(subset=["frame.time"])

timeline = (
    df_time
    .set_index("frame.time")
    .resample("1min")
    .size()
)

print("\nTIMELINE SUMMARY\n")
print(f"Start: {timeline.index.min()}")
print(f"End:   {timeline.index.max()}")
print(f"Peak traffic: {timeline.max()} packets/min")

print("\nTop 10 busiest minutes:\n")
print(timeline.sort_values(ascending=False).head(10))

plt.figure(figsize=(15, 5))
timeline.plot()

plt.title("Network Activity Timeline")
plt.xlabel("Time")
plt.ylabel("Packets per Minute")

plt.tight_layout()
plt.savefig(output_plot_path)
plt.show()

print("\nTimeline graph saved.")


# %% PHASE 6 - PEAK ACTIVITY DATASET CREATION


import subprocess

pcap_path = "/x.pcap/"
peak_output_path = "/x.tsv/"

peak_minutes = [
    "2025-01-22 20:45:00+01:00",
    "2025-01-22 20:47:00+01:00",
    "2025-01-22 20:59:00+01:00",
    "2025-01-22 21:25:00+01:00",
    "2025-01-22 21:28:00+01:00"
]

cmd = [
    "tshark",
    "-r", pcap_path,
    "-T", "fields",

    "-e", "frame.number",
    "-e", "frame.time",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "_ws.col.Protocol",

    "-e", "dns.qry.name",
    "-e", "tls.handshake.extensions_server_name",
    "-e", "http.host",

    "-E", "header=y",
    "-E", "separator=\t",
    "-E", "occurrence=f"
]

with open(peak_output_path, "w") as f:
    subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)

df_peak = pd.read_csv(peak_output_path, sep="\t")

df_peak["frame.time"] = pd.to_datetime(df_peak["frame.time"], errors="coerce")
df_peak = df_peak.dropna(subset=["frame.time"])

peak_frames = []

for minute in peak_minutes:
    start = pd.Timestamp(minute)
    end = start + pd.Timedelta(minutes=1)

    peak_frames.append(
        df_peak[(df_peak["frame.time"] >= start) & (df_peak["frame.time"] < end)]
    )

df_peak = pd.concat(peak_frames, ignore_index=True)

print("\nPEAK IOC SURFACE READY")
print("Total peak packets:", len(df_peak))


# %% PHASE 6.1 - PEAK ACTIVITY ANALYSIS


print("\nTOP EXTERNAL IPS DURING PEAKS\n")

external_ips = pd.concat([
    df_peak["ip.src"],
    df_peak["ip.dst"]
]).value_counts()

external_ips = external_ips[
    ~external_ips.index.astype(str).str.startswith("10.")
]

print(external_ips.head(10))


external_targets = [
    "45.125.66.32",
    "5.252.153.241",
    "82.221.136.26",
    "23.55.125.176"
]

for ip in external_targets:

    print("\n" + "=" * 60)
    print(f"IOC PIVOT: {ip}")
    print("=" * 60)

    df_ip = df_peak[
        (df_peak["ip.src"] == ip) |
        (df_peak["ip.dst"] == ip)
    ]

    print(f"PACKETS OBSERVED: {len(df_ip)}")

    dns_hits = df_ip["dns.qry.name"].dropna().unique()
    tls_hits = df_ip["tls.handshake.extensions_server_name"].dropna().unique()

    http_hits = []
    if "http.host" in df_ip.columns:
        http_hits = df_ip["http.host"].dropna().unique()

    print("\nDNS IDENTIFIERS:", dns_hits if len(dns_hits) else "None")
    print("\nTLS IDENTIFIERS:", tls_hits if len(tls_hits) else "None")
    print("\nHTTP IDENTIFIERS:", http_hits if len(http_hits) else "None")

    print("\nPROTOCOL PROFILE:")
    print(df_ip["_ws.col.Protocol"].value_counts())


# %% PHASE 7 - IOC CORRELATION


ioc_ips = [
    "45.125.66.252",
    "45.125.66.32",
    "5.252.153.241",
    "82.221.136.26",
    "23.55.125.176"
]

df_ioc = df[
    df["ip.src"].isin(ioc_ips) |
    df["ip.dst"].isin(ioc_ips)
].copy()

print(df_ioc["_ws.col.protocol"].value_counts())

for ip in ioc_ips:

    subset = df_ioc[
        (df_ioc["ip.src"] == ip) |
        (df_ioc["ip.dst"] == ip)
    ]

    print(ip)
    print(subset["frame.time"].min())
    print(subset["frame.time"].max())

    timeline = (
        df_ioc
        .set_index("frame.time")
        .resample("1min")
        .size()
    )


# %% PHASE 7.1 - TEMPORAL CORRELATION


import matplotlib.pyplot as plt

df_graph = df[
    df["ip.src"].isin(ioc_ips) |
    df["ip.dst"].isin(ioc_ips)
].copy()

df_graph["minute"] = df_graph["frame.time"].dt.floor("1min")

plt.figure(figsize=(15, 8))

for ip in ioc_ips:

    temp = df_graph[
        (df_graph["ip.src"] == ip) |
        (df_graph["ip.dst"] == ip)
    ]

    counts = temp.groupby("minute").size()

    plt.plot(
        counts.index,
        counts.values,
        marker="o",
        label=ip
    )

plt.title("IOC: IP Communication Timeline")
plt.xlabel("Time")
plt.ylabel("Packets per Minute")
plt.legend()
plt.xticks(rotation=45)

plt.tight_layout()
plt.savefig("/x/.png")
plt.show()

for ip in ioc_ips:

    temp = df_graph[
        (df_graph["ip.src"] == ip) |
        (df_graph["ip.dst"] == ip)
    ]

    counts = temp.groupby("minute").size()

    print("\n====================")
    print(ip)
    print("====================")
    print(counts.sort_values(ascending=False).head(10))


# %% PHASE 7.2 - C2 BEHAVIOUR


import pandas as pd

suspicious_ips = [
    "45.125.66.32",
    "45.125.66.252",
    "5.252.153.241",
    "82.221.136.26",
    "23.55.125.176"
]

df_sess = df[
    df["ip.src"].isin(suspicious_ips) |
    df["ip.dst"].isin(suspicious_ips)
].copy()

df_sess["frame.time"] = pd.to_datetime(df_sess["frame.time"], errors="coerce")
df_sess = df_sess.sort_values("frame.time")

has_stream = "tcp.stream" in df_sess.columns
has_flags = "tcp.flags.syn" in df_sess.columns

print("tcp.stream available:", has_stream)
print("tcp.flags available:", has_flags)

results = []

for ip in suspicious_ips:

    temp = df_sess[
        (df_sess["ip.src"] == ip) |
        (df_sess["ip.dst"] == ip)
    ].copy()

    if temp.empty:
        continue

    temp = temp.sort_values("frame.time")

    if has_stream:
        grouped = temp.groupby("tcp.stream")
    else:
        temp["delta"] = temp["frame.time"].diff().dt.total_seconds()
        temp["session_id"] = (temp["delta"] > 60).cumsum()
        grouped = temp.groupby("session_id")

    session_packets = grouped.size()

    session_duration = grouped["frame.time"].agg(
        lambda x: (x.max() - x.min()).total_seconds()
    )

    short = (session_duration < 10).sum()
    medium = ((session_duration >= 10) & (session_duration < 60)).sum()
    long = (session_duration >= 60).sum()

    syn = fin = rst = None

    if has_flags:
        syn = temp["tcp.flags.syn"].fillna(0).astype(int).sum()
        fin = temp["tcp.flags.fin"].fillna(0).astype(int).sum()
        rst = temp["tcp.flags.reset"].fillna(0).astype(int).sum()

    results.append({
        "ip": ip,
        "num_sessions": len(grouped),
        "avg_packets_per_session": session_packets.mean(),
        "avg_session_duration_sec": session_duration.mean(),
        "short_sessions": short,
        "medium_sessions": medium,
        "long_sessions": long,
        "SYN": syn,
        "FIN": fin,
        "RST": rst
    })

df_c2_behavior = pd.DataFrame(results)

print("\nC2 BEHAVIOR SUMMARY\n")
print(df_c2_behavior)

df_c2_behavior.to_csv("data/c2_behavior.csv", index=False)


# %% PHASE 7.3 - C2 COMMUNICATION BEHAVIOR


import pandas as pd

ips = [
    "5.252.153.241",
    "45.125.66.32",
    "82.221.136.26",
    "45.125.66.252",
    "23.55.125.176"
]

df["frame.time"] = pd.to_datetime(df["frame.time"], errors="coerce")
df = df.dropna(subset=["frame.time"])

results = []

for ip in ips:

    temp = df[(df["ip.src"] == ip) | (df["ip.dst"] == ip)].copy()

    if temp.empty:
        continue

    temp = temp.sort_values("frame.time")

    total_packets = len(temp)

    unique_peers = len(set(temp["ip.src"]).union(set(temp["ip.dst"]))) - 1

    duration_sec = (
        temp["frame.time"].max() - temp["frame.time"].min()
    ).total_seconds()

    pkt_rate = total_packets / duration_sec if duration_sec > 0 else 0

    temp["delta"] = temp["frame.time"].diff().dt.total_seconds()
    deltas = temp["delta"].dropna()

    if len(deltas) > 5:
        mean_delta = deltas.mean()
        std_delta = deltas.std()
        jitter = std_delta / mean_delta if mean_delta > 0 else 0
    else:
        mean_delta = std_delta = jitter = None

    per_min = temp.set_index("frame.time").resample("1min").size()

    burstiness = per_min.std() / per_min.mean() if per_min.mean() > 0 else 0

    score = 0

    if pkt_rate > 1:
        score += 1

    if jitter is not None and jitter < 0.5:
        score += 2

    if burstiness < 1:
        score += 1

    if score >= 3:
        classification = "High C2 likelihood"
    elif score == 2:
        classification = "Suspicious communication"
    else:
        classification = "Likely benign / noisy traffic"

    results.append({
        "ip": ip,
        "packets": total_packets,
        "unique_peers": unique_peers,
        "duration_sec": duration_sec,
        "pkt_rate_per_sec": pkt_rate,
        "mean_interval": mean_delta,
        "jitter": jitter,
        "burstiness": burstiness,
        "c2_score": score,
        "classification": classification
    })

df_c2_final = pd.DataFrame(results)

print("\nC2 CLASSIFICATION\n")
print(df_c2_final)

df_c2_final.to_csv(
    "/x/",
    index=False
)


# %% PHASE 8 - VICTIM IDENTIFICATION


import pandas as pd
import matplotlib.pyplot as plt

pcap_path = "/x/"

df = pd.read_csv(pcap_path, sep="\t")

df["frame.time"] = pd.to_datetime(df["frame.time"], errors="coerce")
df = df.sort_values("frame.time")

victim_ip = "10.1.17.215"

victim_traffic = df[
    (df["ip.src"] == victim_ip) | (df["ip.dst"] == victim_ip)
].copy()

print("Total victim packets:", len(victim_traffic))
print(victim_traffic["_ws.col.protocol"].value_counts())


# %% PHASE 8.1 - VICTIM PROFILING

first_seen = victim_traffic["frame.time"].min()
last_seen = victim_traffic["frame.time"].max()

print("First activity:", first_seen)
print("Last activity:", last_seen)

dns_victim = victim_traffic[
    victim_traffic["_ws.col.protocol"] == "DNS"
]

print("\nTOP DNS QUERIES:")
print(df_dns["dns.qry.name"].value_counts().head(20))

internal_prefix = "10."

df_ext = victim_traffic[
    ~victim_traffic["ip.dst"].astype(str).str.startswith(internal_prefix)
]

top_external = df_ext["ip.dst"].value_counts()

print("\nTOP EXTERNAL COMMUNICATIONS:")
print(top_external.head(10))

timeline = victim_traffic.set_index("frame.time").resample("1min").size()

print("\nPEAK ACTIVITY:")
print(timeline.sort_values(ascending=False).head(10))

timeline.plot(
    figsize=(15, 5),
    title="Victim Activity Timeline"
)

plt.savefig(
    "/x/"
)

print("\nPROTOCOL EVOLUTION:")
print(victim_traffic["_ws.col.protocol"].value_counts())

# %% PHASE 8.1 - VICTIM PROFILING 1

first_seen = victim_traffic["frame.time"].min()
last_seen = victim_traffic["frame.time"].max()

print("First activity:", first_seen)
print("Last activity:", last_seen)

dns_victim = victim_traffic[
    victim_traffic["_ws.col.protocol"] == "DNS"
]

print("\nTOP DNS QUERIES:")
print(
    df_dns["dns.qry.name"].value_counts().head(20)
)

internal_prefix = "10."

df_ext = victim_traffic[
    ~victim_traffic["ip.dst"].astype(str).str.startswith(internal_prefix)
]

top_external = df_ext["ip.dst"].value_counts()

print("\nTOP EXTERNAL COMMUNICATIONS:")
print(top_external.head(10))

timeline = victim_traffic.set_index("frame.time")
timeline_1min = timeline.resample("1min").size()

print("\nPEAK ACTIVITY:")
print(timeline_1min.sort_values(ascending=False).head(10))

timeline_1min.plot(
    figsize=(15, 5),
    title="Victim Activity Timeline"
)

plt.savefig("/x/.png")

print("\nPROTOCOL EVOLUTION:")
print(victim_traffic["_ws.col.protocol"].value_counts())


# %% PHASE 9 - VICTIM RESULTS

import pandas as pd

pcap_path = "data/pcap_output.tsv"
dns_path = "data/dns_output.csv"

df_pcap = pd.read_csv(pcap_path, sep="\t")
df_dns = pd.read_csv(dns_path, sep="|")

victim_ip = "10.1.17.215"

victim_mac = (
    df_pcap[df_pcap["ip.src"] == victim_ip]["eth.src"]
    .value_counts()
    .idxmax()
)

first_seen = pd.to_datetime(df_pcap["frame.time"], errors="coerce").min()
last_seen = pd.to_datetime(df_pcap["frame.time"], errors="coerce").max()

hostnames = [
    h for h in df_dns["dns.qry.name"].dropna().unique()
    if "bluemoontuesday" in str(h).lower()
]

domain_hits = df_dns[
    df_dns["dns.qry.name"].str.contains("bluemoontuesday", na=False)
]["dns.qry.name"].unique()

protocols = (
    df_pcap["_ws.col.protocol"]
    .value_counts()
    .head(10)
    .reset_index()
)

protocols.columns = ["protocol", "count"]

env_summary = [
    {"field": "Question", "value": "Evidence Source Summary"},
    {"field": "User", "value": "shutchenson"},
    {"field": "Hostname", "value": "DESKTOP-L8C5GSJ"},
    {"field": "Domain", "value": "BLUEMOONTUESDAY.COM"},
    {"field": "AD Environment", "value": "BLUEMOONTUESDAY"},
    {"field": "Kerberos Activity", "value": "Yes"},
    {"field": "Domain Controller", "value": "10.1.17.2 (WIN-GSH54QLW48D)"},
    {"field": "Gateway", "value": "10.1.17.1"},
    {"field": "LAN Range", "value": "10.1.17.0/24"},
    {"field": "Authentication Domain", "value": "BLUEMOONTUESDAY.COM"},
    {"field": "Evidence Source", "value": "Kerberos ticket requests observed during lateral movement analysis"},
]

dynamic_summary = [
    {"field": "Victim IP", "value": victim_ip},
    {"field": "Victim MAC", "value": victim_mac},
    {"field": "First seen", "value": first_seen},
    {"field": "Last seen", "value": last_seen},
    {"field": "Top Protocols", "value": protocols.to_string(index=False)},
    {"field": "Detected Hostnames", "value": "; ".join(hostnames)},
    {"field": "Domain-related Activity", "value": "; ".join(domain_hits)},
]

df_env = pd.DataFrame(env_summary + dynamic_summary)

output_path = "data/victim_summary.csv"
df_env.to_csv(output_path, index=False)

print("[OK] Victim summary saved")


# %% PHASE 9.1 - IOC TIMELINE

import pandas as pd

timeline = [
    {
        "timestamp": "2025-01-22 20:45:36",
        "event_type": "INITIAL_COMPROMISE_INDICATOR",
        "source": "10.1.17.215",
        "destination": "82.221.136.26",
        "details": "TLS SNI -> authenticatoor.org",
        "confidence": "High"
    },
    {
        "timestamp": "2025-01-22 20:47:00",
        "event_type": "BOOTSTRAP_ACTIVITY",
        "source": "10.1.17.215",
        "destination": "5.252.153.241",
        "details": "Initial burst (>5600 packets / 30s)",
        "confidence": "High"
    },
    {
        "timestamp": "2025-01-22 20:59:30",
        "event_type": "C2_STAGE_START",
        "source": "10.1.17.215",
        "destination": "45.125.66.32",
        "details": "First major activity spike",
        "confidence": "Medium"
    },
    {
        "timestamp": "2025-01-22 21:00:00",
        "event_type": "SECONDARY_NODE_START",
        "source": "10.1.17.215",
        "destination": "45.125.66.252",
        "details": "Secondary TLS communications begin",
        "confidence": "Medium"
    },
    {
        "timestamp": "2025-01-22 21:25:00",
        "event_type": "COORDINATED_ACTIVITY",
        "source": "C2_CLUSTER",
        "destination": "Victim Host",
        "details": "Multi-node synchronization detected",
        "confidence": "Medium"
    }
]

df_timeline = pd.DataFrame(timeline)

output_path = "/x/.csv"

df_timeline.to_csv(output_path, index=False)

print("IOC timeline exported")
print(df_timeline)


# %% PHASE 9.2 - IOC ENRICHMENT

import socket
import json
import pandas as pd
import urllib.request


ips = [
    "5.252.153.241",
    "45.125.66.32",
    "45.125.66.252",
    "82.221.136.26",
    "23.55.125.176"
]

domains = [
    "authenticatoor.org",
    "bluemoontuesday.com",
    "ping3.dyngate.com",
    "google-authenticator.burleson-appliance.net"
]


def asn_lookup(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.load(response)

        return {
            "type": "ip",
            "ioc": ip,
            "asn": data.get("org", "N/A"),
            "country": data.get("country", "N/A"),
            "city": data.get("city", "N/A")
        }

    except Exception:
        return {
            "type": "ip",
            "ioc": ip,
            "asn": "NOT_AVAILABLE",
            "country": "NOT_AVAILABLE",
            "city": "NOT_AVAILABLE"
        }


def dns_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "NOT_RESOLVED"


results = []

print("DOMAIN ENRICHMENT")

for d in domains:
    results.append({
        "type": "domain",
        "ioc": d,
        "resolved_ip": dns_lookup(d)
    })

print("IP ENRICHMENT")

for ip in ips:
    results.append(asn_lookup(ip))


df = pd.DataFrame(results)

output_path = "/x/.csv"
df.to_csv(output_path, index=False)

print("[OK] IOC enrichment saved")


# PHASE 9.3 WHOIS

import subprocess
import pandas as pd

ips = [
    "5.252.153.241",
    "45.125.66.32",
    "45.125.66.252",
    "82.221.136.26",
    "23.55.125.176"
]

def clean_whois(ip):

    result = subprocess.run(
        ["whois", ip],
        capture_output=True,
        text=True
    )

    lines = result.stdout.splitlines()

    keywords = [
        "origin",
        "originas",
        "org",
        "organisation",
        "netname",
        "descr",
        "country",
        "route",
        "abuse"
    ]

    filtered = [
        line for line in lines
        if any(k in line.lower() for k in keywords)
    ]

    return "\n".join(filtered)

results = []

for ip in ips:
    print(f"Processing WHOIS: {ip}")

    results.append({
        "ip": ip,
        "whois_summary": clean_whois(ip)
    })

df = pd.DataFrame(results)

output_path = "/x/.csv"

df.to_csv(output_path, index=False)

print(f"[OK] WHOIS summary saved: {output_path}")


# PHASE 9.4 IOC TABLE 

import pandas as pd

ioc_enrichment = [
    {
        "Type": "Domain",
        "IOC": "authenticatoor.org",
        "Evidence": "TLS SNI observed during initial compromise window",
        "Category": "Suspicious authentication phishing / staging domain",
        "Confidence": "High"
    },
    {
        "Type": "IP",
        "IOC": "82.221.136.26",
        "Evidence": "TLS SNI correlation with fake authentication domain",
        "Category": "Suspicious hosting / staging infrastructure",
        "Confidence": "High"
    },
    {
        "Type": "IP",
        "IOC": "5.252.153.241",
        "Evidence": "High-volume bootstrap traffic during initial peak phase",
        "Category": "Suspicious external host (bootstrap activity)",
        "Confidence": "Medium-High"
    },
    {
        "Type": "IP",
        "IOC": "45.125.66.32",
        "Evidence": "Sustained peak traffic and coordinated communication pattern",
        "Category": "Suspicious external infrastructure node (primary)",
        "Confidence": "Medium"
    },
    {
        "Type": "IP",
        "IOC": "45.125.66.252",
        "Evidence": "Secondary sustained communication pattern",
        "Category": "Suspicious external infrastructure node (secondary)",
        "Confidence": "Medium"
    },
    {
        "Type": "IP",
        "IOC": "23.55.125.176",
        "Evidence": "High-volume TLS traffic consistent with CDN delivery (Akamai)",
        "Category": "High-volume CDN infrastructure (likely benign noise)",
        "Confidence": "Low (contextual relevance only)"
    },
    {
        "Type": "ASN",
        "IOC": "AS133398",
        "Evidence": "HostBaltic infrastructure hosting 45.125.66.0/24 range",
        "Category": "Hosting provider (infrastructure correlation)",
        "Confidence": "Medium"
    },
    {
        "Type": "Domain",
        "IOC": "bluemoontuesday.com",
        "Evidence": "Identified as internal AD domain traffic",
        "Category": "Internal infrastructure (non-malicious)",
        "Confidence": "High"
    }
]

df = pd.DataFrame(ioc_enrichment)

output_path = "/x/.csv"

df.to_csv(output_path, index=False)

print("IOC enrichment table saved to:", output_path)
print(df)
