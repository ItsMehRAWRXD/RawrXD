import requests
r = requests.get('https://huggingface.co/api/models/deepseek-ai/DeepSeek-V2-Lite-Chat')
data = r.json()
siblings = data.get('siblings', [])
for s in siblings:
    name = s.get('rfilename', '')
    size = s.get('size', 0)
    if 'safetensors' in name.lower() and size:
        print(f"{name}: {size/1024/1024/1024:.2f} GB")
