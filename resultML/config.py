import torch

class Config:
    """
    Configuration for binary classification
    """
    def __init__(self):
        # Model
        self.hidden_size     = 128      # hidden dim LSTM
        self.num_layers      = 2        # jumlah layer LSTM
        self.dropout         = 0.3      # dropout di classifier
        self.embedding_dim   = 300       # embedding dim
        self.numeric_dim     = 4        # jumlah fitur numerik
        self.num_classes     = 2        # output 2 kelas

        # Training
        self.batch_size    = 32
        self.epochs        = 20
        self.learning_rate = 0.001

        # Data processing
        self.max_length    = 80
        self.threshold     = 0.5

        # Device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class MulticlassConfig(Config):
    """
    Configuration for multiclass classification
    """
    def __init__(self):
        # Model
        self.hidden_size     = 128      # hidden dim LSTM
        self.num_layers      = 2        # jumlah layer LSTM
        self.dropout         = 0.3      # dropout di classifier
        self.embedding_dim   = 300       # embedding dim
        self.numeric_dim     = 4        # jumlah fitur numerik
        self.num_classes     = 6        # output 6 kelas
        
        # Training
        self.batch_size = 32
        self.epochs = 20
        self.learning_rate = 0.001
        
        # Data
        self.max_length = 80
        self.num_classes = 6

        # Device
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
