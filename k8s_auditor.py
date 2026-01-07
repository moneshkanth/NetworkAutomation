import yaml

def audit_k8s_manifest(yaml_content):
    """
    Audits a K8s YAML manifest for SRE best practices.
    Returns:
        score (int): 0-100 stability score.
        findings (list): List of dicts {'severity': 'high|medium|low', 'msg': '...'}
    """
    findings = []
    score = 100
    
    try:
        # Load all documents if multiple
        docs = list(yaml.safe_load_all(yaml_content))
    except Exception as e:
        return 0, [{'severity': 'critical', 'msg': f"Invalid YAML: {str(e)}"}]
    
    if not docs:
        return 0, [{'severity': 'critical', 'msg': "Empty manifest."}]

    for doc in docs:
        if not doc: continue
        
        kind = doc.get("kind", "Unknown")
        name = doc.get("metadata", {}).get("name", "Unnamed")
        
        # We focus on Pod-spec owners: Deployment, StatefulSet, DaemonSet, Pod
        spec = None
        if kind == "Pod":
            spec = doc.get("spec", {})
        elif kind in ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"]:
            spec = doc.get("spec", {}).get("template", {}).get("spec", {})
        
        if not spec:
            continue
            
        containers = spec.get("containers", [])
        
        for c in containers:
            c_name = c.get("name", "unknown")
            
            # 1. Resource Limits (Efficiency/Stability)
            resources = c.get("resources", {})
            requests = resources.get("requests", {})
            limits = resources.get("limits", {})
            
            if not requests.get("cpu") or not requests.get("memory"):
                score -= 10
                findings.append({'severity': 'medium', 'msg': f"[{kind}/{name}] Container '{c_name}' missing resource requests."})
            
            if not limits.get("cpu") or not limits.get("memory"):
                score -= 5
                findings.append({'severity': 'low', 'msg': f"[{kind}/{name}] Container '{c_name}' missing resource limits."})
                
            # 2. Probes (Reliability)
            # CronJobs/Jobs don't usually need probes
            if kind not in ["Job", "CronJob"]:
                if not c.get("livenessProbe"):
                    score -= 15
                    findings.append({'severity': 'high', 'msg': f"[{kind}/{name}] Container '{c_name}' missing livenessProbe."})
                
                if not c.get("readinessProbe"):
                    score -= 15
                    findings.append({'severity': 'high', 'msg': f"[{kind}/{name}] Container '{c_name}' missing readinessProbe."})
            
            # 3. Security (Security)
            security = c.get("securityContext", {})
            if security.get("privileged") is True:
                score -= 20
                findings.append({'severity': 'critical', 'msg': f"[{kind}/{name}] Container '{c_name}' running in PRIVILEGED mode."})
                
            if security.get("runAsUser") == 0:
                 score -= 10
                 findings.append({'severity': 'high', 'msg': f"[{kind}/{name}] Container '{c_name}' running as ROOT (UID 0)."})
                 
            # 4. Image Tag (Reliability)
            image = c.get("image", "")
            if ":latest" in image or ":" not in image:
                score -= 5
                findings.append({'severity': 'medium', 'msg': f"[{kind}/{name}] Container '{c_name}' using 'latest' tag (non-deterministic)."})

    # Clamp score
    return max(0, score), findings
