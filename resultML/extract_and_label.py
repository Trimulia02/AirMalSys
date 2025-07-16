#!/usr/bin/env python3
import os
import json
import argparse
import pandas as pd

def extract_one(rep_path, label):
    """Extract features from report.json and return as dict."""
    r = json.load(open(rep_path))
    feats = {}

    # --- Sequence features: exec & dropped exe ---
    procs, paths = [], []
    for sig in r.get("signatures", []):
        if sig.get("name") == "executes_dropped_exe":
            for entry in sig.get("iocs", {}).get("iocs", []):
                i = entry.get("ioc", {})
                procs.append(i.get("process", ""))
                paths.append(i.get("path", ""))
    feats["exec_processes_seq"] = procs
    feats["exec_paths_seq"] = paths
    feats["num_execs"] = len(procs)
    feats["num_unique_execs"] = len(set(procs))

    # --- Sequence features: DNS queries (name + type) ---
    dns = r.get("network", {}).get("dns", {}).get("query", [])
    dns_queries = [d.get("name", "") for d in dns]
    dns_types = [d.get("type", "") for d in dns]
    feats["dns_queries_seq"] = dns_queries
    feats["dns_types_seq"] = dns_types
    feats["num_dns_queries"] = len(dns_queries)

    # --- Sequence features: UDP flows (ports, sizes, timestamps) ---
    udp = r.get("network", {}).get("udp", [])
    udp_ports = [f"{u.get('srcport')}->{u.get('dstport')}" for u in udp]
    udp_src_ports = [u.get("srcport") for u in udp]
    udp_dst_ports = [u.get("dstport") for u in udp]
    udp_sizes = [u.get("size", 0) for u in udp]
    udp_timestamps = [u.get("ts") for u in udp]
    feats["udp_ports_seq"] = udp_ports
    feats["udp_src_ports_seq"] = udp_src_ports
    feats["udp_dst_ports_seq"] = udp_dst_ports
    feats["udp_sizes_seq"] = udp_sizes
    feats["udp_timestamps_seq"] = udp_timestamps
    feats["num_udp_packets"] = len(udp)

    # --- Sequence features: Hosts ---
    hosts = r.get("network", {}).get("host", [])
    feats["hosts_seq"] = hosts
    feats["num_hosts"] = len(hosts)

    # --- Sequence features: Signature names ---
    sig_names = [sig.get("name", "") for sig in r.get("signatures", [])]
    feats["sig_names_seq"] = sig_names

    # --- Sequence features: MITRE TTP events ---
    ttps = [t.get("id", "") for t in r.get("ttps", [])]
    feats["ttps_seq"] = ttps
    feats["num_ttps"] = len(ttps)

    # --- Sequence features: Process events ---
    proc_list = r.get("processes", {}).get("process_list", [])
    proc_names = [p.get("name", "") for p in proc_list]
    process_states = [p.get("state", "") for p in proc_list]
    injection_flags = [p.get("injected", False) for p in proc_list]
    parent_procids = [p.get("parent_procid") for p in proc_list]
    start_ts = [p.get("start_ts") for p in proc_list]
    feats["processes_seq"] = proc_names
    feats["process_states_seq"] = process_states
    feats["injection_flags_seq"] = injection_flags
    feats["parent_procid_seq"] = parent_procids
    feats["start_ts_seq"] = start_ts
    feats["num_processes"] = len(proc_list)

    # --- Sequence features: Screenshot similarity scores ---
    screenshots = r.get("screenshot", [])
    screenshot_scores = [s.get("match", 0) for s in screenshots]
    feats["screenshot_scores_seq"] = screenshot_scores

    # --- Static label ---
    feats["label"] = label
    return feats


def collect(analyses_root, label):
    rows = []
    for root, dirs, files in os.walk(analyses_root):
        if "report.json" in files:
            path = os.path.join(root, "report.json")
            feats = extract_one(path, label)
            rows.append(feats)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--analyses", required=True, help="Cuckoo analyses root")
    p.add_argument("--out",      required=True, help="Output CSV file")
    p.add_argument("--label",    type=int, default=1, help="1=malware,0=benign")
    args = p.parse_args()

    df = collect(args.analyses, args.label)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} rows to {args.out}")

