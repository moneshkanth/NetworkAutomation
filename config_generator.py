import jinja2
import json
import pandas as pd
import zipfile
import io

def generate_bulk_configs(template_str, df):
    """
    Generates configs from a CSV DataFrame and zips them.
    
    Args:
        template_str (str): The Jinja2 template.
        df (pd.DataFrame): The CSV data.
        
    Returns:
        tuple: (zip_bytes, preview_list)
    """
    preview = []
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        template = jinja2.Template(template_str)
        
        # Iterate over rows
        for index, row in df.iterrows():
            data = row.to_dict()
            
            # Render
            try:
                config_content = template.render(**data)
                
                # Determine Filename (use 'hostname' column if exists, else row index)
                # Santize filename
                if 'hostname' in data:
                    filename = f"{data['hostname']}.txt"
                else:
                    filename = f"config_row_{index+1}.txt"
                
                # Add to Zip
                zip_file.writestr(filename, config_content)
                
                # Add to preview (limit to first 3)
                if len(preview) < 3:
                     preview.append({"filename": filename, "content": config_content})
                     
            except Exception as e:
                # Log error in content if render fails
                err_msg = f"Error rendering row {index}: {str(e)}"
                zip_file.writestr(f"error_row_{index}.txt", err_msg)
                if len(preview) < 3:
                    preview.append({"filename": f"error_{index}", "content": err_msg})

    zip_buffer.seek(0)
    return zip_buffer, preview

def generate_configs(data):
    """
    Generates network configurations for multiple vendors based on input data.
    
    Args:
        data (dict): A dictionary containing:
            - vlan_id (str/int)
            - ip_address (str) (e.g., "192.168.1.1/24")
            - interface_name (str)
            - mtu (str/int)
            
    Returns:
        dict: Keys are vendor names, values are the rendered config strings.
    """
    
    # Pre-process data if needed
    # For SONiC, we might want just the IP without CIDR for some keys, 
    # but ConfigDB usually keys by "Interface|IP/Mask".
    
    templates = {
        "Cisco NX-OS": """
interface {{ interface_name }}
  description Link_to_Server_VLAN_{{ vlan_id }}
  no switchport
  mtu {{ mtu }}
  ip address {{ ip_address }}
  no shutdown
exit

vlan {{ vlan_id }}
  name VLAN_{{ vlan_id }}
  state active
exit
""",
        "Juniper Junos": """
set interfaces {{ interface_name }} description "Link_to_Server_VLAN_{{ vlan_id }}"
set interfaces {{ interface_name }} mtu {{ mtu }}
set interfaces {{ interface_name }} unit 0 family inet address {{ ip_address }}
set vlans v{{ vlan_id }} vlan-id {{ vlan_id }}
""",
        "Microsoft SONiC": """
{
    "INTERFACE": {
        "{{ interface_name }}": {
            "mtu": {{ mtu }}
        },
        "{{ interface_name }}|{{ ip_address }}": {}
    },
    "VLAN": {
        "Vlan{{ vlan_id }}": {
            "vlanid": {{ vlan_id }}
        }
    },
    "VLAN_MEMBER": {
        "Vlan{{ vlan_id }}|{{ interface_name }}": {
            "tagging_mode": "tagged"
        }
    }
}
"""
    }

    results = {}
    
    for vendor, template_str in templates.items():
        try:
            template = jinja2.Template(template_str.strip())
            rendered = template.render(**data)
            
            # For JSON, validate/format it strictly if it's SONiC
            if vendor == "Microsoft SONiC":
                # Ensure it's valid JSON (Jinja might leave trailing commas if we aren't careful, 
                # but our template is simple). 
                # Let's simple-parse re-dump to pretty print it perfectly.
                try:
                    parsed = json.loads(rendered)
                    rendered = json.dumps(parsed, indent=4)
                except:
                    pass # Keep raw text if it fails parsing (e.g. user input broke structure)
            
            results[vendor] = rendered
        except Exception as e:
            results[vendor] = f"Error generating config: {str(e)}"
            
    return results
