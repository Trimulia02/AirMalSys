import torch
import torch.nn as nn
import pandas as pd
import numpy as np
import pickle
import joblib
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder

class Config:
    def __init__(self):
        # Model parameters
        self.hidden_size = 128
        self.dropout = 0.3
        self.max_length = 80
        self.threshold = 0.5
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class MulticlassConfig:
    def __init__(self):
        # Model parameters
        self.hidden_size = 128
        self.dropout = 0.3
        self.max_length = 80
        self.num_classes = 6
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

class BiLSTM(nn.Module):
    """Binary classification model"""
    def __init__(self, vocab_size, config):
        super(BiLSTM, self).__init__()
        
        self.embedding = nn.Embedding(vocab_size, 64, padding_idx=0)
        self.lstm = nn.LSTM(64, config.hidden_size, batch_first=True, bidirectional=True)
        
        self.classifier = nn.Sequential(
            nn.Linear(config.hidden_size * 2 + 4, 64),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(64, 2)
        )
        
    def forward(self, sequence, numeric):
        embedded = self.embedding(sequence)
        lstm_out, (hidden, _) = self.lstm(embedded)
        
        # Use last hidden state
        hidden = torch.cat((hidden[-2], hidden[-1]), dim=1)
        
        # Combine features
        combined = torch.cat((hidden, numeric), dim=1)
        output = self.classifier(combined)
        
        return output

class MulticlassBiLSTM(nn.Module):
    """Multiclass classification model"""
    def __init__(self, vocab_size, config):
        super(MulticlassBiLSTM, self).__init__()
        
        self.embedding = nn.Embedding(vocab_size, 64, padding_idx=0)
        self.lstm = nn.LSTM(64, config.hidden_size, batch_first=True, bidirectional=True)
        
        self.classifier = nn.Sequential(
            nn.Linear(config.hidden_size * 2 + 4, 64),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(64, 6)  # 6 classes
        )
        
    def forward(self, sequence, numeric):
        embedded = self.embedding(sequence)
        lstm_out, (hidden, _) = self.lstm(embedded)
        
        # Use last hidden state
        hidden = torch.cat((hidden[-2], hidden[-1]), dim=1)
        
        # Combine features
        combined = torch.cat((hidden, numeric), dim=1)
        output = self.classifier(combined)
        
        return output

class MalwareInference:
    """Unified inference class for both binary and multiclass models"""
    
    def __init__(self):
        self.binary_model = None
        self.multiclass_model = None
        self.vocab = None
        self.scaler = None
        self.label_encoder = None
        self.binary_config = Config()
        self.multiclass_config = MulticlassConfig()
        self.class_names = ['adware', 'ransomware', 'rootkit', 'trojan', 'coinminer', 'keylogger']
        
    def load_models(self, model_dir='model', multiclass_dir='model_multiclass'):
        """Load both binary and multiclass models"""
        try:
            # Load vocabulary and scaler (shared between models)
            with open(os.path.join(model_dir, 'vocab.pkl'), 'rb') as f:
                self.vocab = pickle.load(f)
            
            self.scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
            
            # Load binary model
            self.binary_model = BiLSTM(len(self.vocab), self.binary_config).to(self.binary_config.device)
            self.binary_model.load_state_dict(torch.load(os.path.join(model_dir, 'simple_bilstm.pth'), 
                                                        map_location=self.binary_config.device))
            
            # Load binary config
            with open(os.path.join(model_dir, 'config.pkl'), 'rb') as f:
                binary_config_dict = pickle.load(f)
                self.binary_config.threshold = binary_config_dict.get('threshold', 0.5)
            
            # Load multiclass model
            self.multiclass_model = MulticlassBiLSTM(len(self.vocab), self.multiclass_config).to(self.multiclass_config.device)
            self.multiclass_model.load_state_dict(torch.load(os.path.join(multiclass_dir, 'multiclass_bilstm.pth'), 
                                                           map_location=self.multiclass_config.device))
            
            # Load label encoder for multiclass
            self.label_encoder = joblib.load(os.path.join(multiclass_dir, 'label_encoder.pkl'))
            
            self.binary_model.eval()
            self.multiclass_model.eval()
            
            print("✅ Models loaded successfully!")
            print(f"   Vocabulary size: {len(self.vocab)}")
            print(f"   Binary threshold: {self.binary_config.threshold:.3f}")
            print(f"   Multiclass classes: {list(self.label_encoder.classes_)}")
            return True
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False
    
    def prepare_input(self, sequence_features, numeric_features):
        """Prepare input data for inference"""
        # Combine sequence features if they're separate
        if isinstance(sequence_features, list):
            sequence = ';'.join([str(x) for x in sequence_features if x and str(x) != 'nan'])
        else:
            sequence = str(sequence_features) if sequence_features else ""
        
        # Process sequence
        if sequence:
            tokens = sequence.split(';')
            indices = [self.vocab.get(token, 1) for token in tokens]  # 1 = <UNK>
        else:
            indices = []
        
        # Pad or truncate to max_length
        if len(indices) > self.binary_config.max_length:
            indices = indices[:self.binary_config.max_length]
        else:
            indices += [0] * (self.binary_config.max_length - len(indices))  # 0 = <PAD>
        
        # Scale numeric features
        numeric_scaled = self.scaler.transform(np.array([numeric_features]))
        
        # Convert to tensors
        seq_tensor = torch.tensor([indices], dtype=torch.long).to(self.binary_config.device)
        num_tensor = torch.tensor(numeric_scaled, dtype=torch.float32).to(self.binary_config.device)
        
        return seq_tensor, num_tensor
    
    def predict_binary(self, sequence_features, numeric_features):
        """Binary prediction: Malware or Benign"""
        if self.binary_model is None:
            raise ValueError("Binary model not loaded. Call load_models() first.")
        
        seq_tensor, num_tensor = self.prepare_input(sequence_features, numeric_features)
        
        with torch.no_grad():
            outputs = self.binary_model(seq_tensor, num_tensor)
            probs = torch.softmax(outputs, dim=1)
            
            malware_prob = probs[0, 1].item()  # Probability of malware class
            confidence = torch.max(probs, dim=1)[0].item()
            prediction = 1 if malware_prob >= self.binary_config.threshold else 0
            
        return {
            'prediction': prediction,
            'label': 'Malware' if prediction == 1 else 'Benign',
            'malware_probability': malware_prob,
            'confidence': confidence
        }
    
    def predict_multiclass(self, sequence_features, numeric_features, confidence_threshold=0.7):
        """Multiclass prediction: Specific malware type or 'other'"""
        if self.multiclass_model is None:
            raise ValueError("Multiclass model not loaded. Call load_models() first.")
        
        seq_tensor, num_tensor = self.prepare_input(sequence_features, numeric_features)
        
        with torch.no_grad():
            outputs = self.multiclass_model(seq_tensor, num_tensor)
            probs = torch.softmax(outputs, dim=1)
            
            predicted_class = torch.argmax(probs, dim=1).item()
            confidence = torch.max(probs, dim=1)[0].item()
            
            # Check if confidence is below threshold → classify as "other"
            if confidence < confidence_threshold:
                class_name = "other"
                predicted_class = -1
            else:
                class_name = self.label_encoder.classes_[predicted_class]
            
            # Get probabilities for all classes
            class_probs = {}
            for i, class_name_i in enumerate(self.label_encoder.classes_):
                class_probs[class_name_i] = probs[0, i].item()
        
        return {
            'predicted_class': predicted_class,
            'class_name': class_name,
            'confidence': confidence,
            'is_other': confidence < confidence_threshold,
            'class_probabilities': class_probs,
            'threshold_used': confidence_threshold
        }
    
    def predict(self, sequence_features, numeric_features, output_format='combined'):
        """
        Unified prediction function
        
        Args:
            sequence_features: List of sequence features or combined string
            numeric_features: List of 4 numeric features [num_execs, num_unique_execs, num_dns_queries, num_udp_packets]
            output_format: 'binary', 'multiclass', or 'combined'
        
        Returns:
            Dictionary with prediction results
        """
        results = {}
        
        if output_format in ['binary', 'combined']:
            binary_result = self.predict_binary(sequence_features, numeric_features)
            results['binary'] = binary_result
        
        if output_format in ['multiclass', 'combined']:
            multiclass_result = self.predict_multiclass(sequence_features, numeric_features)
            results['multiclass'] = multiclass_result
        
        # Combined output in requested format
        if output_format == 'combined':
            if results['binary']['label'] == 'Malware':
                malware_type = results['multiclass']['class_name']
                final_label = f"Malware ({malware_type})" if malware_type != 'other' else "Malware (unknown type)"
            else:
                final_label = "Benign"
                
            results['final'] = {
                'label': final_label,
                'malware_probability': results['binary']['malware_probability'],
                'malware_type': results['multiclass']['class_name'] if results['binary']['label'] == 'Malware' else None,
                'confidence': results['binary']['confidence']
            }
        
        return results

def main():
    """Example usage"""
    # Initialize inference
    detector = MalwareInference()
    
    # Load models
    if not detector.load_models():
        print("Failed to load models. Make sure model files exist.")
        return
    
    print("\n" + "="*60)
    print("🔍 MALWARE DETECTION INFERENCE")
    print("="*60)
    
    # Example 1: Using separate sequence features
    print("\n📝 Example 1: Separate sequence features")
    sequence_features = ['calc.exe', 'notepad.exe', 'cmd.exe']
    numeric_features = [3, 2, 5, 8]  # [num_execs, num_unique_execs, num_dns_queries, num_udp_packets]
    
    # Binary prediction
    binary_result = detector.predict(sequence_features, numeric_features, output_format='binary')
    print(f"Binary: {binary_result['binary']['label']}")
    print(f"Malware Probability: {binary_result['binary']['malware_probability']:.4f}")
    
    # Combined prediction
    combined_result = detector.predict(sequence_features, numeric_features, output_format='combined')
    print(f"Final: {combined_result['final']['label']}")
    print(f"Malware Probability: {combined_result['final']['malware_probability']:.4f}")
    
    # Example 2: Using combined sequence string
    print("\n📝 Example 2: Combined sequence string")
    sequence_string = "powershell.exe;cmd.exe;svchost.exe"
    numeric_features = [5, 3, 12, 15]
    
    result = detector.predict(sequence_string, numeric_features, output_format='combined')
    print(f"Binary: {result['binary']['label']}")
    print(f"Malware Probability: {result['binary']['malware_probability']:.4f}")
    print(f"Final: {result['final']['label']}")
    
    if result['binary']['label'] == 'Malware':
        print(f"Malware Type: {result['multiclass']['class_name']}")
        print(f"Type Confidence: {result['multiclass']['confidence']:.4f}")
    
    # Example 3: Simple format (like your request)
    print("\n📝 Example 3: Simple format")
    def simple_predict(sequence_features, numeric_features):
        """Simple prediction function matching your output format"""
        result = detector.predict(sequence_features, numeric_features, output_format='combined')
        
        if result['binary']['label'] == 'Malware':
            malware_type = result['multiclass']['class_name']
            if malware_type != 'other':
                return f"Malware ({malware_type})", result['binary']['malware_probability']
            else:
                return "Malware", result['binary']['malware_probability']
        else:
            return "Benign", result['binary']['malware_probability']
    
    # Test cases
    test_cases = [
        (['malware.exe', 'trojan.dll'], [2, 2, 10, 5]),
        (['notepad.exe', 'calc.exe'], [2, 2, 1, 0]),
        (['suspicious.exe', 'keylogger.dll'], [3, 2, 8, 12])
    ]
    
    for i, (seq, num) in enumerate(test_cases, 1):
        label, prob = simple_predict(seq, num)
        print(f"Test {i}: {label}")
        print(f"         {prob:.2f}")
        print()

if __name__ == "__main__":
    main()