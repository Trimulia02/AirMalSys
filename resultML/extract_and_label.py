#!/usr/bin/env python3
import os, json, argparse, pandas as pd


def extract_one(rep_path, label):
    """Extract features from report.json and return as dict."""
    r = json.load(open(rep_path))
    feats = {}

    # --- Sequence features ---
    procs, paths = [], []
    for sig in r.get("signatures", []):
        name = sig.get("name", "")
        if name == "executes_dropped_exe":
            for entry in sig.get("iocs", {}).get("iocs", []):
                i = entry["ioc"]
                p = i.get("process")
                q = i.get("path")
                if p:
                    procs.append(p)
                if q:
                    paths.append(q)
    feats["exec_processes"] = ";".join(procs)
    feats["exec_paths"]     = ";".join(paths)

    # --- Derived numeric features ---
    feats["num_execs"] = len(procs)
    feats["num_unique_execs"] = len(set(procs))

    # --- Network features from JSON ---
    net = r.get("network", {})
    feats["num_dns_queries"] = len(net.get("dns", {}).get("query", []))
    feats["num_udp_packets"] = len(net.get("udp", []))

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
        "exec_processes",
        "exec_paths",
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