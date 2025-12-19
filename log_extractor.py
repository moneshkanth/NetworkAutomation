import re
import pandas as pd

def extract_patterns(text, mode):
    """
    Extracts patterns from text based on mode.
    Modes:
    - 'IPv4': Extracts IPv4 addresses.
    - 'Email': Extracts email addresses.
    - 'Errors': Filters lines containing 'error' or 'fail'.
    """
    if not text:
        return {"error": "No text provided."}

    unique_results = []
    count = 0
    
    try:
        if mode == 'IPv4':
            # Basic IPv4 Regex
            pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            matches = re.findall(pattern, text)
            # Filter valid IPs (0-255) to be safe, but simple regex is usually enough for log scraping
            unique_results = sorted(list(set(matches)))
            count = len(unique_results)
            
        elif mode == 'Email':
            # Basic Email Regex
            pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            matches = re.findall(pattern, text)
            unique_results = sorted(list(set(matches)))
            count = len(unique_results)
            
        elif mode == 'Errors':
            # Line-based filter
            lines = text.split('\n')
            error_pattern = re.compile(r'(error|fail|exception)', re.IGNORECASE)
            matches = [line.strip() for line in lines if error_pattern.search(line)]
            unique_results = matches # Duplicates might be significant in logs (e.g. repeated errors)
            count = len(unique_results)
            
        return {
            "mode": mode,
            "count": count,
            "results": unique_results
        }
    except Exception as e:
        return {"error": str(e)}
