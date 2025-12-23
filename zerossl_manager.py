import requests
import streamlit as st
import pandas as pd
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# API Base URL
BASE_URL = "https://api.zerossl.com"

def generate_key_and_csr(common_name):
    """
    Generates a Private Key and CSR for the given Common Name.
    Returns: (private_key_pem, csr_pem) strings.
    """
    # 1. Generate Private Key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # 2. Generate CSR
    # Note: ZeroSSL just needs CN.
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(key, hashes.SHA256())
    
    # 3. Serialize to PEM
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    return key_pem, csr_pem

@st.cache_data(ttl=300) # Cache for 5 minutes
def list_certificates(api_key):
    """
    Fetches the list of certificates from ZeroSSL.
    Endpoint: GET /certificates?access_key={api_key}
    """
    url = f"{BASE_URL}/certificates"
    params = {'access_key': api_key}
    
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if 'error' in data:
            return {"error": data['error']['type']}
            
        return data.get('results', [])
    except Exception as e:
        return {"error": str(e)}

def get_certificate_download_link(cert_id, api_key):
    """
    Returns the download link for a certificate.
    Technically typically GET /certificates/{id}/download/return?access_key={api_key}
    But for simple UI we might just fetch the content or show the link.
    """
    return f"{BASE_URL}/certificates/{cert_id}/download/return?access_key={api_key}"

def create_certificate(api_key, domains, csr=None, validity_days=90):
    """
    Creates a new certificate via ZeroSSL API.
    Endpoint: POST /certificates
    """
    url = f"{BASE_URL}/certificates"
    params = {'access_key': api_key}
    
    data = {
        'certificate_domains': domains,
        'certificate_validity_days': validity_days,
    }
    
    if csr:
        data['certificate_csr'] = csr
        
    try:
        # User-Agent is good practice
        headers = {'User-Agent': 'NetworkAutomationDashboard/1.0'}
        response = requests.post(url, params=params, data=data, headers=headers, timeout=15)
        
        try:
            resp_json = response.json()
        except:
            return {"error": f"Invalid JSON response: {response.text}"}

        if 'error' in resp_json:
            return {"error": resp_json['error']['type'], "details": resp_json['error']}
            
        return resp_json

    except Exception as e:
        return {"error": str(e)}
