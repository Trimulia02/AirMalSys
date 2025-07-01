#!/usr/bin/env python3
import os, json, argparse, pandas as pd


def extract_one(rep_path, label):
    """Extract features from report.json and return as dict."""
    r = json.load(open(rep_path))
    feats = {}

    # --- Sequence features: exec & dropped exe ---
    procs, paths = [], []
    for sig in r.get("signatures", []):
        name = sig.get("name", "")
        if name == "executes_dropped_exe":
            for entry in sig.get("iocs", {}).get("iocs", []):
                i = entry.get("ioc", {})
                p = i.get("process")
                q = i.get("path")
                if p:
                    procs.append(p)
                if q:
                    paths.append(q)
    feats["exec_processes_seq"] = ";".join(procs)
    feats["exec_paths_seq"]     = ";".join(paths)

    # --- Additional sequence features ---
    net = r.get("network", {})

    # DNS queries sequence
    dns_queries = [q.get("name", "") for q in net.get("dns", {}).get("query", [])]
    feats["dns_queries_seq"] = ";".join(dns_queries)

    # UDP ports sequence
    udp_entries = net.get("udp", [])
    udp_ports = [f"{u.get('srcport')}->{u.get('dstport')}" for u in udp_entries]
    feats["udp_ports_seq"] = ";".join(udp_ports)

    # Hosts sequence
    hosts = net.get("host", [])
    feats["hosts_seq"] = ";".join(hosts)

    # Signature names sequence
    sig_names = [sig.get("name", "") for sig in r.get("signatures", [])]
    feats["sig_names_seq"] = ";".join(sig_names)

    # Timestamps sequence (DNS & UDP)
    ts_list = [q.get("ts") for q in net.get("dns", {}).get("query", []) if q.get("ts") is not None]
    ts_list += [u.get("ts") for u in udp_entries if u.get("ts") is not None]
    ts_list = sorted(ts_list)
    feats["timestamps_seq"] = ";".join(str(ts) for ts in ts_list)

    # --- Derived numeric features ---
    feats["num_execs"] = len(procs)
    feats["num_unique_execs"] = len(set(procs))
    feats["num_dns_queries"] = len(dns_queries)
    feats["num_udp_packets"] = len(udp_entries)

    # --- Label ---
    feats["label"] = label
    return feats


def collect(root, label):
    rows = []
    for dirpath, _, files in os.walk(os.path.expanduser(root)):
        if "report.json" in files:
            rep = os.path.join(dirpath, "report.json")
            rows.append(extract_one(rep, label))
    # define column order explicitly
    columns = [
        "exec_processes_seq",
        "exec_paths_seq",
        "dns_queries_seq",
        "udp_ports_seq",
        "hosts_seq",
        "sig_names_seq",
        "timestamps_seq",
        "num_execs",
        "num_unique_execs",
        "num_dns_queries",
        "num_udp_packets",
        "label"
    ]
    return pd.DataFrame(rows, columns=columns)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--analyses", required=True, help="Cuckoo analyses root")
    p.add_argument("--out",      required=True, help="Output CSV file")
    p.add_argument("--label",    type=int, default=1, help="1=malware,0=benign")
    args = p.parse_args()

    df = collect(args.analyses, args.label)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} rows to {args.out}")
