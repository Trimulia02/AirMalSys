import os
import torch
import json
import pandas as pd
import numpy as np
from typing import Dict, Union

from config import Config, MulticlassConfig
from preprocessing import load_vocab, load_scaler, load_label_encoder, MalwareDataset
from model import BiLSTM


def extract_features_from_report(report_path: str) -> Dict:
    """
    Extract features dari report.json (sama seperti extract_and_label.py)
    
    Args:
        report_path: Path ke report.json
    
    Returns:
        Dictionary dengan extracted features
    """
    with open(report_path, 'r') as f:
        r = json.load(f)
    
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
    feats["exec_paths_seq"] = ";".join(paths)

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

    # --- Derived numeric features ---
    feats["num_execs"] = len(procs)
    feats["num_unique_execs"] = len(set(procs))
    feats["num_dns_queries"] = len(dns_queries)
    feats["num_udp_packets"] = len(udp_entries)

    return feats


class MalwareInference:
    """
    Inference class untuk pipeline: Binary → Multiclass detection
    """
    
    def __init__(self, artifacts_dir: str = "artifacts"):
        """
        Args:
            artifacts_dir: folder yang berisi model dan preprocessing artifacts
        """
        self.artifacts_dir = artifacts_dir
        
        # Load configs
        self.binary_cfg = Config()
        self.multiclass_cfg = MulticlassConfig()
        
        # Model paths
        self.binary_model_path = os.path.join(artifacts_dir, "binary_model.pth")
        self.multiclass_model_path = os.path.join(artifacts_dir, "multiclass_model.pth")
        
        # Threshold untuk "Other" di multiclass
        self.confidence_threshold = 0.6
        
        # Load preprocessing artifacts
        self._load_preprocessing_artifacts()
        
        # Load models
        self._load_models()
        
        print("✅ Binary dan Multiclass models loaded successfully!")
    
    def _load_preprocessing_artifacts(self):
        """Load vocab, scaler, dan label encoder"""
        vocab_path = os.path.join(self.artifacts_dir, "vocab.pkl")
        scaler_path = os.path.join(self.artifacts_dir, "scaler.pkl")
        label_encoder_path = os.path.join(self.artifacts_dir, "label_encoder.pkl")
        
        self.vocab = load_vocab(vocab_path)
        self.scaler = load_scaler(scaler_path)
        self.label_encoder = load_label_encoder(label_encoder_path)
        
        # Multiclass class names
        self.multiclass_classes = list(self.label_encoder.classes_)
    
    def _load_models(self):
        """Load binary dan multiclass models"""
        # Binary model
        self.binary_model = BiLSTM(vocab_size=len(self.vocab), cfg=self.binary_cfg)
        self.binary_model.load_state_dict(torch.load(self.binary_model_path, map_location=self.binary_cfg.device))
        self.binary_model.to(self.binary_cfg.device)
        self.binary_model.eval()
        
        # Multiclass model
        self.multiclass_model = BiLSTM(vocab_size=len(self.vocab), cfg=self.multiclass_cfg)
        self.multiclass_model.load_state_dict(torch.load(self.multiclass_model_path, map_location=self.multiclass_cfg.device))
        self.multiclass_model.to(self.multiclass_cfg.device)
        self.multiclass_model.eval()
    
    def preprocess_features(self, features: Dict) -> tuple:
        """
        Preprocess extracted features untuk model input
        
        Args:
            features: Dictionary dari extract_features_from_report()
        
        Returns:
            Tuple of (sequence_tensor, numeric_tensor)
        """
        # Build sequence (sama seperti di training)
        sequence_cols = [
            'exec_processes_seq', 'exec_paths_seq', 'dns_queries_seq',
            'udp_ports_seq', 'hosts_seq', 'sig_names_seq'
        ]
        
        parts = []
        for col in sequence_cols:
            val = features.get(col, "")
            if val and pd.notna(val) and val != "":
                parts.append(str(val))
        
        sequence = ';'.join(parts) if parts else ""
        
        # Build numeric features
        numeric_cols = ['num_execs', 'num_unique_execs', 'num_dns_queries', 'num_udp_packets']
        numeric_values = []
        for col in numeric_cols:
            val = features.get(col, 0)
            numeric_values.append(float(val) if val is not None else 0.0)
        
        numeric_array = np.array([numeric_values])
        
        # Create dummy dataset untuk preprocessing
        dummy_dataset = MalwareDataset(
            sequences=[sequence],
            numeric_features=numeric_array,
            labels=[0],  # dummy label
            vocab=self.vocab,
            scaler=self.scaler,
            label_encoder=self.label_encoder,
            max_length=self.binary_cfg.max_length  # sama untuk binary dan multiclass
        )
        
        # Get processed tensors
        sample = dummy_dataset[0]
        seq_tensor = sample["sequence"].unsqueeze(0)  # Add batch dim
        num_tensor = sample["numeric"].unsqueeze(0)   # Add batch dim
        
        return seq_tensor, num_tensor
    
    def predict_binary(self, seq_tensor: torch.Tensor, num_tensor: torch.Tensor) -> tuple:
        """
        Predict dengan binary model
        
        Returns:
            Tuple of (is_malware: bool, malware_probability: float)
        """
        seq_tensor = seq_tensor.to(self.binary_cfg.device)
        num_tensor = num_tensor.to(self.binary_cfg.device)
        
        with torch.no_grad():
            logits = self.binary_model(seq_tensor, num_tensor)
            probs = torch.softmax(logits, dim=1)
            malware_prob = probs[0, 1].item()  # Probability of malware
            
            # Check threshold
            is_malware = malware_prob > self.binary_cfg.threshold
            
            return is_malware, malware_prob
    
    def predict_multiclass(self, seq_tensor: torch.Tensor, num_tensor: torch.Tensor) -> tuple:
        """
        Predict dengan multiclass model
        
        Returns:
            Tuple of (malware_type: str, confidence: float)
        """
        seq_tensor = seq_tensor.to(self.multiclass_cfg.device)
        num_tensor = num_tensor.to(self.multiclass_cfg.device)
        
        with torch.no_grad():
            logits = self.multiclass_model(seq_tensor, num_tensor)
            probs = torch.softmax(logits, dim=1)
            prob_values = probs[0].cpu().numpy()
            
            # Get prediction
            predicted_idx = np.argmax(prob_values)
            max_confidence = prob_values[predicted_idx]
            
            # Check confidence threshold
            if max_confidence < self.confidence_threshold:
                malware_type = "Other"
            else:
                malware_type = self.multiclass_classes[predicted_idx].capitalize()
            
            return malware_type, max_confidence
    
    def predict_pipeline(self, features: Dict) -> Dict:
        """
        Full pipeline: Binary → Multiclass (jika malware)
        
        Args:
            features: Extracted features dari report.json
        
        Returns:
            Dictionary dengan hasil prediksi
        """
        # Preprocess
        seq_tensor, num_tensor = self.preprocess_features(features)
        
        # Step 1: Binary classification
        is_malware, malware_prob = self.predict_binary(seq_tensor, num_tensor)
        
        if not is_malware:
            # Benign case
            return {
                "result": "Benign",
                "probability": f"{malware_prob:.1f}",
                "malware_type": None
            }
        else:
            # Malware case - lanjut ke multiclass
            malware_type, confidence = self.predict_multiclass(seq_tensor, num_tensor)
            
            return {
                "result": "Malware", 
                "probability": f"{malware_prob:.1f}",
                "malware_type": malware_type
            }
    
    def predict_from_report(self, report_path: str, output_path: str = "ml_result.txt"):
        """
        Predict dari report.json dan save ke ml_result.txt
        
        Args:
            report_path: Path ke report.json
            output_path: Path output file (default: ml_result.txt)
        """
        # Extract features
        features = extract_features_from_report(report_path)
        
        # Predict
        result = self.predict_pipeline(features)
        
        # Write output
        with open(output_path, 'w') as f:
            if result["result"] == "Benign":
                f.write(f"{result['result']}\n")
                f.write(f"{result['probability']}\n")
            else:  # Malware
                f.write(f"{result['result']}\n")
                f.write(f"{result['probability']}\n")
                f.write(f"{result['malware_type']}\n")
        
        print(f"✅ Prediction saved to {output_path}")
        print(f"Result: {result['result']}")
        if result["result"] == "Malware":
            print(f"Type: {result['malware_type']}")
        print(f"Probability: {result['probability']}")
        
        return result


def main():
    """
    Contoh penggunaan inference
    """
    # Contoh simple usage
    report_path = "report.json"  # Ganti dengan path report.json kamu
    
    # Initialize inference
    inference = MalwareInference()
    
    # Predict dan save ke ml_result.txt
    result = inference.predict_from_report(report_path)
    
    return result


# Function untuk dipanggil dari script lain
def run_inference(report_json_path: str, output_file: str = "ml_result.txt", artifacts_dir: str = "artifacts"):
    """
    Function utama untuk dipanggil dari script lain
    
    Args:
        report_json_path: Path ke report.json dari Cuckoo3
        output_file: Path output file (default: ml_result.txt)  
        artifacts_dir: Directory artifacts model (default: artifacts)
    
    Returns:
        Dictionary dengan hasil prediksi
    """
    try:
        # Initialize inference
        inference = MalwareInference(artifacts_dir=artifacts_dir)
        
        # Run prediction
        result = inference.predict_from_report(report_json_path, output_file)
        
        return result
        
    except Exception as e:
        print(f"❌ Error during inference: {str(e)}")
        return None


if __name__ == "__main__":
    main()