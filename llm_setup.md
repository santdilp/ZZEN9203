# Local LLM Setup for IoT Device Analysis

## Option 1: Ollama (Recommended)

### Install Ollama:
```bash
# Download from https://ollama.ai/download
# Or use winget on Windows:
winget install Ollama.Ollama
```

### Pull a small model:
```bash
ollama pull llama2:7b-chat    # ~4GB
# or smaller:
ollama pull phi3:mini         # ~2GB
ollama pull gemma:2b          # ~1.4GB
```

### Start Ollama service:
```bash
ollama serve
```

### Test the API:
```bash
curl http://localhost:11434/api/generate -d '{
  "model": "phi3:mini",
  "prompt": "Analyze this IoT device: Meross smart light bulb with open ports 80, 443",
  "stream": false
}'
```

## Option 2: LM Studio (GUI)

1. Download LM Studio from https://lmstudio.ai/
2. Install a small model like `microsoft/Phi-3-mini-4k-instruct-gguf`
3. Start local server on port 1234
4. Modify script to use `http://localhost:1234/v1/chat/completions`

## Option 3: Python with Transformers

```python
pip install transformers torch

# Use in script:
from transformers import pipeline
generator = pipeline('text-generation', model='microsoft/DialoGPT-small')
```

## Usage Examples:

```bash
# Force scan single host with LLM analysis
python getdevice-enhanced.py 192.168.4.80 --force --llm

# Debug mode
python getdevice-enhanced.py 192.168.4.80 --force --debug --llm

# Scan range without LLM
python getdevice-enhanced.py 192.168.1.0/24 --force
```

## Benefits of Local LLM:

1. **Privacy**: No data sent to external APIs
2. **Speed**: No network latency
3. **Cost**: No API fees
4. **Customization**: Can fine-tune for security analysis
5. **Offline**: Works without internet

## LLM Analysis Features:

- Device type identification
- Security vulnerability assessment  
- Risk scoring
- Mitigation recommendations
- Protocol analysis
- Behavioral insights