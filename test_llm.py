import requests
import json

def test_ollama():
    """Test Ollama connection and available models"""
    
    # Test connection
    try:
        response = requests.get('http://localhost:11434/api/tags', timeout=5)
        if response.status_code == 200:
            models = response.json()
            print("Available models:")
            for model in models.get('models', []):
                print(f"  - {model['name']}")
            
            # Test with first available model
            if models.get('models'):
                model_name = models['models'][0]['name']
                print(f"\nTesting with model: {model_name}")
                
                test_response = requests.post('http://localhost:11434/api/generate',
                    json={
                        'model': model_name,
                        'prompt': 'What is an IoT device? Answer in 2 sentences.',
                        'stream': False
                    },
                    timeout=30)
                
                if test_response.status_code == 200:
                    result = test_response.json()
                    print(f"Response: {result.get('response', 'No response')}")
                    return model_name
                else:
                    print(f"Generate failed: {test_response.status_code}")
            else:
                print("No models found")
        else:
            print(f"Connection failed: {response.status_code}")
    
    except requests.exceptions.ConnectionError:
        print("Ollama not running. Start with: ollama serve")
    except Exception as e:
        print(f"Error: {e}")
    
    return None

if __name__ == "__main__":
    model = test_ollama()
    if model:
        print(f"\nUse this model name in the script: {model}")