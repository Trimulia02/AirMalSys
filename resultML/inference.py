import os
import torch
import json
import pandas as pd
import numpy as np
from typing import Dict

from config import Config, MulticlassConfig
from preprocessing import load_vocab, load_scaler, load_label_encoder, MalwareDataset
from model import BiLSTM

def extract_features_from_report(report_path: str):
    with open(report_path) as f:
        r = json.load(f)
    feats = {}

    # --- exec processes (exact same logic) ---
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

    # dns
    dns = r.get("network", {}).get("dns", {}).get("query", [])
    feats["dns_queries_seq"] = [d.get("name","") for d in dns]
    feats["dns_types_seq"]   = [d.get("type","") for d in dns]
    feats["num_dns_queries"] = len(dns)

    # udp
    udp = r.get("network", {}).get("udp", [])
    feats["udp_ports_seq"] = [f"{u.get('srcport')}->{u.get('dstport')}" for u in udp]
    feats["num_udp_packets"] = len(udp)

    # hosts
    hosts = r.get("network", {}).get("host", [])
    feats["hosts_seq"] = hosts
    feats["num_hosts"] = len(hosts)

    # signatures (names)
    sig_names = [s.get("name","") for s in r.get("signatures", [])]
    feats["sig_names_seq"] = sig_names

    # ttps
    ttps = [t.get("id","") for t in r.get("ttps", [])]
    feats["ttps_seq"] = ttps
    feats["num_ttps"] = len(ttps)

    # processes list
    proc_list = r.get("processes", {}).get("process_list", [])
    feats["processes_seq"] = [p.get("name","") for p in proc_list]
    feats["num_processes"] = len(proc_list)

    return feats

class MalwareInference:
    def __init__(self, artifacts_dir: str = "artifacts"):
        self.artifacts_dir = artifacts_dir
        self.binary_cfg = Config()
        self.multiclass_cfg = MulticlassConfig()

        self.binary_model_path = os.path.join(artifacts_dir, "binary_model.pth")
        self.multiclass_model_path = os.path.join(artifacts_dir, "multiclass_model.pth")

        self._load_preprocessing_artifacts()
        self._load_models()
        print("✅ Binary dan Multiclass models loaded successfully!")

    def _load_preprocessing_artifacts(self):
        self.vocab = load_vocab(os.path.join(self.artifacts_dir, "vocab.pkl"))
        self.scaler_binary = load_scaler(os.path.join(self.artifacts_dir, "scaler_binary.pkl"))
        self.scaler_multi = load_scaler(os.path.join(self.artifacts_dir, "scaler_multi.pkl"))
        self.label_encoder = load_label_encoder(os.path.join(self.artifacts_dir, "label_encoder.pkl"))
        self.multiclass_classes = list(self.label_encoder.classes_)

        self.binary_features = [
            'num_unique_execs', 'num_dns_queries', 
            'network_activity_ratio', 'hosts_per_query',
            "num_execs", 'hosts_seq_length', "num_hosts",
            "num_ttps", "num_processes", "exec_diversity_ratio",
            "network_activity_ratio", "seq_length", "seq_unique_count",
            "sig_names_seq_length", "signatures_density", 'num_udp_packets',
        ]
        self.multi_features = [
            "seq_diversity", "num_execs", "num_dns_queries", "num_hosts", "num_ttps",
            "seq_length", "seq_unique_count", "hosts_seq_length", "sig_names_seq_length",
            "exec_diversity_ratio", "hosts_per_query", "signatures_density",
            "num_unique_execs", "num_udp_packets", "num_processes", "network_activity_ratio"
        ]

    def _load_models(self):
        self.binary_model = BiLSTM(vocab_size=len(self.vocab), cfg=self.binary_cfg)
        self.binary_model.load_state_dict(torch.load(self.binary_model_path, map_location=self.binary_cfg.device))
        self.binary_model.to(self.binary_cfg.device).eval()

        self.multiclass_model = BiLSTM(vocab_size=len(self.vocab), cfg=self.multiclass_cfg)
        self.multiclass_model.load_state_dict(torch.load(self.multiclass_model_path, map_location=self.multiclass_cfg.device))
        self.multiclass_model.to(self.multiclass_cfg.device).eval()

    def preprocess_features(self, features: Dict, mode: str = "binary") -> tuple:
        sequence_cols = [
            "exec_processes_seq","exec_paths_seq","dns_queries_seq","dns_types_seq",
            "udp_ports_seq","hosts_seq","sig_names_seq","ttps_seq","processes_seq"
        ]
        parts = []
        for col in sequence_cols:
            vals = features.get(col, [])
            if isinstance(vals, (list, tuple)):
                parts.extend(str(x) for x in vals)
        sequence = ";".join(parts)

        # Hitung engineered features
        feats = features.copy()
        feats['hosts_seq_length'] = len(feats.get("hosts_seq", []))
        feats['sig_names_seq_length'] = len(feats.get("sig_names_seq", []))
        feats['exec_diversity_ratio'] = feats.get("num_unique_execs", 0) / (feats.get("num_execs", 0) + 1)
        feats['network_activity_ratio'] = feats.get("num_dns_queries", 0) / (feats.get("num_udp_packets", 0) + 1)
        feats['hosts_per_query'] = feats['hosts_seq_length'] / (feats.get("num_dns_queries", 0) + 1)
        feats['signatures_density'] = feats['sig_names_seq_length'] / (feats.get("num_execs", 0) + 1)
        feats['seq_length'] = len(parts)
        feats['seq_unique_count'] = len(set(parts))
        feats['seq_diversity'] = feats['seq_unique_count'] / (feats['seq_length'] + 1)

        if mode == "binary":
            numeric_keys = self.binary_features
            scaler = self.scaler_binary
            cfg = self.binary_cfg
        else:
            numeric_keys = self.multi_features
            scaler = self.scaler_multi
            cfg = self.multiclass_cfg

        numeric_values = [float(feats.get(k, 0)) for k in numeric_keys]
        numeric_scaled = scaler.transform([numeric_values])

        dummy_dataset = MalwareDataset(
            sequences=[sequence],
            numeric_features=numeric_scaled,
            labels=[0],
            vocab=self.vocab,
            scaler=scaler,
            label_encoder=self.label_encoder,
            max_length=cfg.max_length
        )
        sample = dummy_dataset[0]
        return sample["sequence"].unsqueeze(0), sample["numeric"].unsqueeze(0)

    def predict_binary(self, seq_tensor: torch.Tensor, num_tensor: torch.Tensor) -> tuple:
        seq_tensor = seq_tensor.to(self.binary_cfg.device)
        num_tensor = num_tensor.to(self.binary_cfg.device)
        with torch.no_grad():
            logits = self.binary_model(seq_tensor, num_tensor)
            probs = torch.softmax(logits, dim=1)
            malware_prob = probs[0, 1].item()
            return malware_prob > self.binary_cfg.threshold, malware_prob

    def predict_multiclass(self, seq_tensor: torch.Tensor, num_tensor: torch.Tensor) -> tuple:
        seq_tensor = seq_tensor.to(self.multiclass_cfg.device)
        num_tensor = num_tensor.to(self.multiclass_cfg.device)
        with torch.no_grad():
            logits = self.multiclass_model(seq_tensor, num_tensor)
            probs = torch.softmax(logits, dim=1)
            prob_values = probs[0].cpu().numpy()
            predicted_idx = np.argmax(prob_values)
            max_conf = prob_values[predicted_idx]
            return self.multiclass_classes[predicted_idx].capitalize(), max_conf

    def predict_pipeline(self, features: Dict) -> Dict:
        seq_tensor, num_tensor = self.preprocess_features(features, mode="binary")
        is_malware, malware_prob = self.predict_binary(seq_tensor, num_tensor)
        if not is_malware:
            return {"result": "Benign", "probability": f"{malware_prob:.1f}", "malware_type": None}
        # Multiclass prediction
        seq_tensor, num_tensor = self.preprocess_features(features, mode="multiclass")
        malware_type, confidence = self.predict_multiclass(seq_tensor, num_tensor)
        return {"result": "Malware", "probability": f"{malware_prob:.1f}", "malware_type": malware_type}
    
    def predict_from_report(self, report_path: str, output_path: str = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt"):
        features = extract_features_from_report(report_path)
        result = self.predict_pipeline(features)
        with open(output_path, 'w') as f:
            if result["result"] == "Benign":
                f.write(f"{result['result']}\n{result['probability']}\n")
            else:
                f.write(f"{result['result']}\n{result['probability']}\n{result['malware_type']}\n")
        print(f"✅ Prediction saved to {output_path}")
        print(f"Result: {result['result']}")
        if result["result"] == "Malware":
            print(f"Type: {result['malware_type']}")
        print(f"Probability: {result['probability']}")
        return result

def run_inference(report_json_path: str,
                  output_file: str = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt",
                  artifacts_dir: str = "artifacts"):
    try:
        inference = MalwareInference(artifacts_dir=artifacts_dir)
        return inference.predict_from_report(report_json_path, output_file)
    except Exception as e:
        print(f"❌ Error during inference: {str(e)}")
        return None

def main():
    """
    CLI interface untuk inference
    """
    import argparse

    parser = argparse.ArgumentParser(description="Malware Detection Inference")
    parser.add_argument("--report", required=True, help="Path to report.json")
    parser.add_argument("--output", default="/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt", help="Output file path")
    parser.add_argument("--artifacts", default="artifacts", help="Artifacts directory")

    args = parser.parse_args()

    inference = MalwareInference(artifacts_dir=args.artifacts)
    inference.predict_from_report(args.report, args.output)

if __name__ == "__main__":
    main()
