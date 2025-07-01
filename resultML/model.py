import torch
import torch.nn as nn

class BiLSTM(nn.Module):
    def __init__(self, vocab_size: int, cfg):
        super().__init__()
        # embedding & LSTM
        self.embedding = nn.Embedding(vocab_size, cfg.embedding_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            input_size   = cfg.embedding_dim,
            hidden_size  = cfg.hidden_size,
            num_layers   = cfg.num_layers,
            bidirectional= True,
            batch_first  = True,
            dropout      = cfg.dropout if cfg.num_layers>1 else 0
        )
        # classifier head: [2*H] + numeric_dim → 64 → num_classes
        self.classifier = nn.Sequential(
        nn.Linear(cfg.hidden_size * 2 + cfg.numeric_dim, cfg.embedding_dim),
        nn.ReLU(),
        nn.Dropout(cfg.dropout),
        nn.Linear(cfg.embedding_dim, cfg.num_classes)
        )

    def forward(self, sequence, numeric):
        emb    = self.embedding(sequence)                # [B, L, 64]
        out, (h, _) = self.lstm(emb)                     # h: [2, B, H]
        last_h = torch.cat((h[-2], h[-1]), dim=1)        # [B, 2*H]
        combined = torch.cat((last_h, numeric), dim=1)   # [B, 2*H+numeric_dim]
        return self.classifier(combined)