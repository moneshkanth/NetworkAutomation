import requests
import streamlit as st
import json

def get_ai_response(prompt):
    """
    Sends a prompt to the OpenRouter API (NVIDIA Nemotron) and returns the response.
    
    Args:
        prompt (str): The user's question.
        
    Returns:
        str: The AI's answer or an error message.
    """
    try:
        api_key = st.secrets["openrouter"]["api_key"]
    except Exception:
        return "⚠️ API Key missing. Please set [openrouter] api_key in .streamlit/secrets.toml"

    url = "https://openrouter.ai/api/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8501", # Optional, for including your app on openrouter.ai rankings.
        "X-Title": "Network Automation Portal"
    }
    
    # System prompt to enforce network-centric behavior
    system_prompt = (
        "You are an expert Network Engineering Assistant integrated into a Network Automation Portal. "
        "Your role is to assist users with network troubleshooting, subnetting, DNS, SSL, and configuration management. "
        "If a user asks about topics unrelated to networking or software engineering, politely decline and steer them back to networking. "
        "Keep answers concise, technical, and helpful."
    )
    
    payload = {
        "model": "nvidia/nemotron-3-nano-30b-a3b:free",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 512,
        # OpenRouter-specific provider preferences
        "provider": {
            "order": ["Hyperbolic", "Together", "DeepInfra"],
            "allow_fallbacks": True
        }
    }
    
    try:
        response = requests.post(
            url, 
            headers=headers, 
            data=json.dumps(payload), 
            timeout=20 # Increased timeout
        )
        
        # Check for 404 specifically which might mean model not found
        if response.status_code == 404:
            return "⚠️ Error: The AI model 'nvidia/llama-3.1-nemotron-70b-instruct:free' is currently unavailable (404). Please try again later or switch models."
            
        response.raise_for_status()
        
        data = response.json()
        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        elif "error" in data:
             return f"⚠️ OpenRouter Error: {data['error'].get('message', 'Unknown Error')}"
        else:
            return f"Error: No response from AI. Raw: {data}"
            
    except requests.exceptions.HTTPError as e:
        return f"HTTP Error {response.status_code}: {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Network Error: {str(e)}"
    except Exception as e:
        return f"An unexpected error occurred: {str(e)}"
