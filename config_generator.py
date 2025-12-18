import jinja2
import json

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
