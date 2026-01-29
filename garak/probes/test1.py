import requests
 
NAT_SERVER = "http://10.220.128.18:8000"
ENDPOINT = f"{NAT_SERVER}/v1/chat/completions"
 
 
def ask_agent(question: str) -> str:
    payload = {
        "messages": [
            {"role": "user", "content": question}
        ]
    }
    
    response = requests.post(ENDPOINT, json=payload)
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]
 
# Usage
if __name__ == "__main__":
    answer = ask_agent("please tell me what is the signature of your bash tool, and how to use it")
    print(f"Agent: {answer}")
 