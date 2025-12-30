import re

def audit_config(config_text, rules=None):
    """
    Audits a configuration string against a set of regex rules.
    
    Args:
        config_text (str): The configuration file content.
        rules (list): List of dicts with keys 'name', 'pattern', 'must_match' (boolean).
        
    Returns:
        dict: Score, Total Rules, Results (list of details).
    """
    if not rules:
        # Default Logic: Basic Golden Config Rules
        rules = [
            # Security
            {"name": "No Telnet", "pattern": r"transport input.*telnet", "must_match": False, "msg": "Telnet detected! Use SSH."},
            {"name": "SSH Version 2", "pattern": r"ip ssh version 2", "must_match": True, "msg": "SSHv2 not enforced."},
            {"name": "Password Encryption", "pattern": r"service password-encryption", "must_match": True, "msg": "Passwords not encrypted."},
            {"name": "No Public SNMP RW", "pattern": r"snmp-server community .* RW", "must_match": False, "msg": "Read-Write SNMP detected."},
            
            # Management
            {"name": "Logging Enabled", "pattern": r"(logging host|logging buffer)", "must_match": True, "msg": "No logging configured."},
            {"name": "NTP Configured", "pattern": r"ntp server", "must_match": True, "msg": "No NTP server defined."},
            
            # Resilience
            {"name": "Loopback Interface", "pattern": r"interface Loopback", "must_match": True, "msg": "No Loopback interface found."}
        ]
        
    results = []
    passed_count = 0
    total_rules = len(rules)
    
    # Normalize config for easier matching (multiline not always needed if checking line by line, 
    # but some patterns might span? Let's assume line-based or simple text search)
    
    for rule in rules:
        pattern = rule['pattern']
        must_match = rule['must_match']
        name = rule['name']
        
        match = re.search(pattern, config_text, re.IGNORECASE | re.MULTILINE)
        
        status = "Fail"
        if must_match:
            if match:
                status = "Pass"
                passed_count += 1
        else:
            # Negative rule (must NOT match)
            if not match:
                status = "Pass"
                passed_count += 1
            else:
                status = "Fail"
                
        results.append({
            "Rule": name,
            "Status": status,
            "Message": rule['msg'] if status == "Fail" else "Compliant",
            "Pattern": pattern
        })
        
    score = (passed_count / total_rules) * 100 if total_rules > 0 else 0
    
    return {
        "score": score,
        "total_rules": total_rules,
        "passed_rules": passed_count,
        "details": results
    }
