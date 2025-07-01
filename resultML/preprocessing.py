import os
import pickle
from collections import Counter

import torch
from torch.utils.data import Dataset
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Vocab
def build_vocab(sequences, pad_token="<PAD>", unk_token="<UNK>"):
    counter = Counter()
    for seq in sequences:
        if isinstance(seq, str):
            counter.update(seq.split(";"))
    vocab = {pad_token: 0, unk_token: 1}
    idx = 2
    for token, _ in counter.most_common():
        vocab[token] = idx
        idx += 1
    return vocab

def save_vocab(vocab: dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(vocab, f)

def load_vocab(path: str) -> dict:
    with open(path, "rb") as f:
        return pickle.load(f)

# Scaler
def build_scaler(numeric_features):
    scaler = StandardScaler()
    scaler.fit(numeric_features)
    return scaler

def save_scaler(scaler: StandardScaler, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(scaler, f)

def load_scaler(path: str) -> StandardScaler:
    with open(path, "rb") as f:
        return pickle.load(f)
    
# Label Encoder (buat Multiclass)
def build_label_encoder(labels):
    le = LabelEncoder()
    le.fit(labels)
    return le

def save_label_encoder(le: LabelEncoder, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        pickle.dump(le, f)

def load_label_encoder(path: str) -> LabelEncoder:
    with open(path, "rb") as f:
        return pickle.load(f)
    
class MalwareDataset(Dataset):
    def __init__(
        self,
        sequences,
        numeric_features,
        labels,
        vocab: dict,
        scaler: StandardScaler,
        label_encoder: LabelEncoder,
        max_length: int
    ):
        self.sequences = sequences
        self.numeric_raw = numeric_features
        self.labels_raw = labels
        self.vocab = vocab
        self.scaler = scaler
        self.le = label_encoder
        self.max_length = max_length

        # Pre-transform numeric features and labels
        self.numeric = self.scaler.transform(self.numeric_raw)
        if isinstance(self.labels_raw[0], str):
            self.labels = self.le.transform(self.labels_raw)
        else:
            self.labels = self.labels_raw

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        # Sequence → token indices
        seq = self.sequences[idx]
        if isinstance(seq, str):
            toks = seq.split(";")
            inds = [self.vocab.get(t, self.vocab.get("<UNK>")) for t in toks]
        else:
            inds = []

        # Pad or truncate
        if len(inds) > self.max_length:
            inds = inds[: self.max_length]
        else:
            inds += [self.vocab.get("<PAD>")] * (self.max_length - len(inds))

        # Create tensors
        seq_tensor = torch.tensor(inds, dtype=torch.long)
        num_tensor = torch.tensor(self.numeric[idx], dtype=torch.float32)
        label_tensor = torch.tensor(self.labels[idx], dtype=torch.long)

        return {
            "sequence": seq_tensor,
            "numeric": num_tensor,
            "label": label_tensor
        }