import torch
import pickle
import os

# Check artifacts directory - artifacts ada di resultML folder
artifacts_dir = "resultML/artifacts"

print("=== DEBUGGING VOCAB MISMATCH ===\n")
print(f"🗂️  Looking for artifacts in: {os.path.abspath(artifacts_dir)}")
print(f"📂 Current working directory: {os.getcwd()}")

# Check if artifacts directory exists
if not os.path.exists(artifacts_dir):
    print(f"❌ Artifacts directory not found: {artifacts_dir}")
    print("📁 Available directories:")
    for item in os.listdir("."):
        if os.path.isdir(item):
            print(f"  - {item}")
    exit(1)

print(f"✅ Artifacts directory found!")
print(f"📁 Files in artifacts:")
for file in os.listdir(artifacts_dir):
    print(f"  - {file}")
print()

# 1. Check vocab.pkl
print("📁 Checking vocab.pkl...")
try:
    with open(os.path.join(artifacts_dir, "vocab.pkl"), "rb") as f:
        vocab = pickle.load(f)
    print(f"✅ Vocab loaded successfully")
    print(f"📊 Vocab size: {len(vocab)}")
    print(f"🔤 First 10 tokens: {list(vocab.items())[:10]}")
    print(f"🔤 Last 10 tokens: {list(vocab.items())[-10:]}")
except Exception as e:
    print(f"❌ Error loading vocab: {e}")

print("\n" + "="*50 + "\n")

# 2. Check binary model
print("📁 Checking binary_model.pth...")
try:
    binary_path = os.path.join(artifacts_dir, "binary_model.pth")
    binary_checkpoint = torch.load(binary_path, map_location='cpu')
    print(f"✅ Binary model loaded successfully")
    
    embedding_weight = binary_checkpoint['embedding.weight']
    print(f"📊 Binary embedding shape: {embedding_weight.shape}")
    print(f"📊 Binary vocab size: {embedding_weight.shape[0]}")
    print(f"📊 Binary embedding dim: {embedding_weight.shape[1]}")
    
    print(f"\n🔍 All keys in binary model:")
    for key in binary_checkpoint.keys():
        shape = binary_checkpoint[key].shape if hasattr(binary_checkpoint[key], 'shape') else 'N/A'
        print(f"  {key}: {shape}")
        
except Exception as e:
    print(f"❌ Error loading binary model: {e}")

print("\n" + "="*50 + "\n")

# 3. Check multiclass model
print("📁 Checking multiclass_model.pth...")
try:
    multiclass_path = os.path.join(artifacts_dir, "multiclass_model.pth")
    multiclass_checkpoint = torch.load(multiclass_path, map_location='cpu')
    print(f"✅ Multiclass model loaded successfully")
    
    embedding_weight = multiclass_checkpoint['embedding.weight']
    print(f"📊 Multiclass embedding shape: {embedding_weight.shape}")
    print(f"📊 Multiclass vocab size: {embedding_weight.shape[0]}")
    print(f"📊 Multiclass embedding dim: {embedding_weight.shape[1]}")
    
    print(f"\n🔍 All keys in multiclass model:")
    for key in multiclass_checkpoint.keys():
        shape = multiclass_checkpoint[key].shape if hasattr(multiclass_checkpoint[key], 'shape') else 'N/A'
        print(f"  {key}: {shape}")
        
except Exception as e:
    print(f"❌ Error loading multiclass model: {e}")

print("\n" + "="*50 + "\n")

# 4. Compare sizes
print("🔄 COMPARISON:")
try:
    vocab_size = len(vocab)
    binary_vocab = binary_checkpoint['embedding.weight'].shape[0]
    multiclass_vocab = multiclass_checkpoint['embedding.weight'].shape[0]
    
    print(f"Current vocab.pkl: {vocab_size}")
    print(f"Binary model expects: {binary_vocab}")
    print(f"Multiclass model expects: {multiclass_vocab}")
    
    if vocab_size == binary_vocab == multiclass_vocab:
        print("✅ All vocab sizes MATCH!")
    else:
        print("❌ MISMATCH detected!")
        print(f"Difference binary: {abs(vocab_size - binary_vocab)}")
        print(f"Difference multiclass: {abs(vocab_size - multiclass_vocab)}")
        
except Exception as e:
    print(f"❌ Error in comparison: {e}")

print("\n" + "="*50 + "\n")

# 5. Check file timestamps
print("📅 File timestamps:")
files_to_check = ["vocab.pkl", "binary_model.pth", "multiclass_model.pth", "scaler.pkl", "label_encoder.pkl"]
for filename in files_to_check:
    filepath = os.path.join(artifacts_dir, filename)
    if os.path.exists(filepath):
        timestamp = os.path.getmtime(filepath)
        import datetime
        readable_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        print(f"  {filename}: {readable_time}")
    else:
        print(f"  {filename}: NOT FOUND")