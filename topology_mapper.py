import re

def parse_lldp_neighbors(raw_text):
    """
    Parses LLDP neighbor output into a list of connections.
    """
    edges = []
    lines = raw_text.splitlines()
    
    for line in lines:
        line = line.strip()
        # Skip headers and empty lines
        if not line or "Device ID" in line or "show lldp" in line or "----" in line:
            continue
            
        parts = line.split()
        if len(parts) >= 4:
            # Assume Generic Cisco/Arista/NX-OS Format:
            # DeviceID (0) ... Local Intf (1 or scattered) ... Port ID (last)
            # Heuristic:
            # 1. Device ID is usually first.
            # 2. Local Intf is usually second (or merged if very long).
            # 3. Port ID is usually last.
            
            remote_device = parts[0]
            # Strip domain names (e.g. switch01.corp.local -> switch01)
            if '.' in remote_device:
                remote_device = remote_device.split('.')[0]
                
            local_intf = parts[1]
            # Identify Port ID (last non-empty token)
            remote_port = parts[-1]
            
            # Simple Validation: Interface usually contains numbers
            if not any(char.isdigit() for char in local_intf):
                # Try next column if col 1 didn't look like an interface
                if len(parts) > 2 and any(char.isdigit() for char in parts[2]):
                    local_intf = parts[2]
            
            edges.append({
                "source": "Local_Device",
                "target": remote_device,
                "label": f"{local_intf} -> {remote_port}"
            })
            
    return edges

def generate_topology_dot(raw_text):
    """
    Generates Graphviz DOT source code from LLDP text.
    
    Args:
        raw_text (str): Raw CLI output.
        
    Returns:
        str: DOT graph description.
    """
    edges = parse_lldp_neighbors(raw_text)
    
    dot = ['graph "LLDP Topology" {']
    dot.append('  rankdir="LR";')
    dot.append('  node [shape=box, style=filled, fillcolor="#E3F2FD", fontname="Helvetica"];')
    dot.append('  edge [fontname="Helvetica", fontsize=10];')
    
    # Highlight Central Node
    dot.append('  "Local_Device" [fillcolor="#FFCCBC", label="📍 This Device", shape=component];')
    
    for edge in edges:
        src = edge['source']
        tgt = edge['target']
        lbl = edge['label']
        # DOT format: "A" -- "B" [label="..."];
        dot.append(f'  "{src}" -- "{tgt}" [label="{lbl}"];')
        
    dot.append('}')
    return "\n".join(dot)
