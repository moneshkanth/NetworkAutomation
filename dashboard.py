import streamlit as st
import pandas as pd
import json
import os
import ipaddress
from network_scanner import scan_network

st.set_page_config(page_title="Network Scanner Dashboard", layout="wide")

import datetime

# Metric Tiles Layout
def display_metrics(df):
    """
    Displays key metrics for the network scan in a 3-column layout.
    
    Args:
        df (pd.DataFrame): The scan results data.
    """
    total_active = len(df)
    port_80_open = df['port_80'].sum() if 'port_80' in df.columns else 0
    ping_responsive = df['ping'].sum() if 'ping' in df.columns else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Active IPs", total_active)
    col2.metric("Port 80 Open", port_80_open)
    col3.metric("Ping Responsive", ping_responsive)

def load_data():
    """
    Loads scan results from `scan_results.json`.
    
    Returns:
        pd.DataFrame: A DataFrame containing scan results or an empty structure if not found.
    """
    file_path = "scan_results.json"
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            if data:
                return pd.DataFrame(data)
            else:
                st.info("No active hosts found.")
                # Show empty dataframe structure
                st.dataframe(pd.DataFrame(columns=["ip", "hostname", "mac", "vendor", "port_80", "ping"]), use_container_width=True)
                return pd.DataFrame(columns=["ip", "hostname", "mac", "vendor", "port_80", "ping"])
        except Exception as e:
            st.error(f"Error loading JSON: {e}")
            return pd.DataFrame(columns=["ip", "hostname", "mac", "vendor", "port_80", "ping"])
    else:
        return pd.DataFrame(columns=["ip", "hostname", "mac", "vendor", "port_80", "ping"])

def append_history(scan_stats, cidr):
    """Appends scan metadata to scan_history.json."""
    history_file = "scan_history.json"
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cidr": cidr,
        "active_count": scan_stats.get('active_count', 0),
        "duration": round(scan_stats.get('duration', 0), 2),
        "total_scanned": scan_stats.get('total_scanned', 0)
    }
    
    history_data = []
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                history_data = json.load(f)
        except:
            history_data = []
            
    # Prepend new entry
    history_data.insert(0, entry)
    
    # Keep last 50
    history_data = history_data[:50]
    
    with open(history_file, 'w') as f:
        json.dump(history_data, f, indent=4)

def load_history():
    """
    Loads scan history from `scan_history.json`.
    
    Returns:
        list: A list of scan history entries.
    """
    history_file = "scan_history.json"
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

# Helpers
def is_private_cidr(cidr):
    """Checks if a CIDR block is within private ranges."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.is_private
    except ValueError:
        return False

import pandas as pd # Ensure pandas is available or use existing import
from config_diff import generate_diff, generate_html_diff
from ssl_checker import check_bulk_ssl
from dns_propagator import check_dns_propagation
from subnet_calculator import calculate_subnet_details
from latency_analyzer import analyze_latency
from ai_assistant import get_ai_response
from config_generator import generate_configs
from network_linter import lint_config
from route_optimizer import optimize_routes
from topology_mapper import generate_topology_dot
from bgp_inspector import get_asn_details, get_asn_peers, get_asn_prefixes, generate_bgp_graph

def save_config_history(old_cfg, new_cfg):
    """Saves config comparison to history."""
    history_file = "config_history.json"
    entry = {
         "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         "old": old_cfg,
         "new": new_cfg,
         "preview": f"Diff @ {datetime.datetime.now().strftime('%H:%M:%S')}"
    }
    
    history_data = []
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                history_data = json.load(f)
        except:
            history_data = []
            
    # Prepend
    history_data.insert(0, entry)
    # Cap at 10
    history_data = history_data[:10]
    
    with open(history_file, 'w') as f:
        json.dump(history_data, f, indent=4)

def load_config_history():
    history_file = "config_history.json"
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_ssl_results(results):
    """Saves SSL scan results to json."""
    try:
        with open("ssl_results.json", 'w') as f:
            json.dump(results, f, indent=4)
    except Exception as e:
        st.error(f"Error saving SSL results: {e}")

def load_ssl_results():
    """Loads last SSL results."""
    if os.path.exists("ssl_results.json"):
        try:
            with open("ssl_results.json", 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def render_config_comparator():
    # Load history state if clicked
    if 'restore_config_index' in st.session_state:
        idx = st.session_state['restore_config_index']
        history = load_config_history()
        if 0 <= idx < len(history):
            st.session_state['old_cfg'] = history[idx]['old']
            st.session_state['new_cfg'] = history[idx]['new']
        # Clear the flag so we don't keep resetting
        del st.session_state['restore_config_index']

    # Sidebar navigation
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Paste your configuration files to see changes.")
        
        st.divider()
        st.subheader("Comparison History")
        history = load_config_history()
        if history:
            for i, item in enumerate(history):
                # Use a button for each history item to restore it
                if st.button(f"🕒 {item['timestamp']}", key=f"hist_{i}"):
                    st.session_state['restore_config_index'] = i
                    st.rerun()
        else:
            st.write("No history yet.")

    st.title("⚖️ Config Comparator")
    st.markdown("Compare two configurations Side-by-Side.")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Old Config")
        # Use session_state key to allow restoration
        old_config = st.text_area("Paste Old Config Here", height=300, key="old_cfg")
    
    with col2:
        st.subheader("New Config")
        new_config = st.text_area("Paste New Config Here", height=300, key="new_cfg")
        
    if st.button("Compare Configs", use_container_width=True):
        if not old_config and not new_config:
            st.warning("Please provide config content to compare.")
        else:
            # Save to history
            save_config_history(old_config, new_config)
            
            # Generate HTML Diff
            html_diff = generate_html_diff(old_config, new_config)
            if html_diff:
                st.subheader("Visual Diff")
                # Render HTML diff
                st.components.v1.html(html_diff, height=600, scrolling=True)
            else:
                st.success("Configs are identical!")

def render_dns_propagator():
    """
    Renders the Global DNS Propagator view.
    """
    # Sidebar navigation
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Querying: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9), OpenDNS (208.67.222.222)")

    st.title("🌍 Global DNS Propagator")
    st.markdown("Verify if your domain resolves correctly across different global providers.")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        domain = st.text_input("Domain Name", "microsoft.com")
    with col2:
        record_type = st.selectbox("Record Type", ["A", "AAAA", "MX", "CNAME", "TXT", "NS"])
        
    if st.button("Check Propagation"):
        if not domain:
            st.warning("Please enter a domain.")
        else:
            with st.spinner(f"Querying global resolvers for {domain} ({record_type})..."):
                results = check_dns_propagation(domain, record_type)
                
                df = pd.DataFrame(results)
                
                # Check consistency
                # A simple consistency check: are all statuses '✅'?
                # Or do all Results match? (Result strings might vary slightly due to ordering, so let's stick to status for now or simple set check)
                
                # Check if all statuses are Check Mark
                all_success = all(r['Status'] == '✅' for r in results)
                
                # Check for result consistency (unique set of results for success entries)
                success_results = [r['Result'] for r in results if r['Status'] == '✅']
                unique_answers = list(set(success_results))
                is_consistent = len(unique_answers) == 1 if success_results else False
                
                if all_success and is_consistent:
                    st.success("✅ Global Consistency Verified: All resolvers returned the same result.")
                elif all_success and not is_consistent:
                    st.warning("⚠️ Inconsistent Results: Providers returned different records (Propagation might be in progress).")
                else:
                    st.error("❌ Propagation Issues: Some providers failed or timed out.")
                
                st.dataframe(df, use_container_width=True)

def render_ssl_inspector():
    """
    Renders the SSL Inspector view, including domain input and bulk checking logic.
    """
    # Sidebar navigation
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Tip: Paste a list of domains like: google.com, github.com, internal-service")

    st.title("🔐 SSL Certificate Inspector")
    st.markdown("Check the expiry status of your critical services.")
    
    # Input Area
    domain_input = st.text_area("Enter Domains (comma separated)", "google.com, github.com, example.com")
    
    if st.button("Check Certificates"):
        if not domain_input.strip():
            st.warning("Please enter at least one domain.")
        else:
            domains = [d.strip() for d in domain_input.split(',')]
            
            with st.spinner(f"Checking {len(domains)} domains..."):
                results = check_bulk_ssl(domains)
                save_ssl_results(results) # Save results
                st.rerun() # Rerun to reload from file and refresh view

    # Load and display details (either just saved or from history)
    saved_data = load_ssl_results()
    if saved_data:
        df = pd.DataFrame(saved_data)
        
        # Metrics
        total = len(df)
        valid = len(df[df['status'] == 'Valid'])
        errors = total - valid
        
        # Identify expiring soon (< 30 days)
        expiring_soon = 0
        if 'days_remaining' in df.columns:
                expiring_soon = len(df[(df['days_remaining'] < 30) & (df['days_remaining'] >= 0)])
        
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Scanned", total)
        m2.metric("Valid Certs", valid)
        m3.metric("Expiring Soon (<30d)", expiring_soon, delta_color="inverse")
        
        st.divider()
        
        # Warning Table for expiring/errors
        if expiring_soon > 0 or errors > 0:
            st.subheader("⚠️ Attention Required")
            problem_df = df[(df['days_remaining'] < 30) | (df['status'] != 'Valid')]
            st.dataframe(problem_df, use_container_width=True)
        
        # Full Table
        st.subheader("All Results")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No previous SSL scan results found. Run a check to see data.")


def render_subnet_calculator():
    """
    Renders the IP Subnet Calculator view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Calculate valid host ranges, broadcast addresses, and masks.")

    st.title("🔢 IP Subnet Visualizer")
    st.markdown("Calculate network boundaries and valid host ranges.")

    cidr_input = st.text_input("Enter CIDR Block", "10.0.0.0/22")

    if cidr_input:
        details = calculate_subnet_details(cidr_input)
        
        if details and "Error" not in details:
            st.success("Valid Subnet Configuration")
            st.divider()
            
            # 2-Column Layout
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"**CIDR:** `{details['CIDR']}`")
                st.markdown(f"**Netmask:** `{details['Netmask']}`")
                st.markdown(f"**Wildcard Mask:** `{details['Wildcard Mask']}`")
                st.markdown(f"**Total Usable Hosts:** `{details['Total Usable Hosts']}`")
                
            with col2:
                st.markdown(f"**Network Address:** `{details['Network Address']}`")
                st.markdown(f"**Broadcast Address:** `{details['Broadcast Address']}`")
                st.markdown(f"**First Usable IP:** `{details['First Usable IP']}`")
                st.markdown(f"**Last Usable IP:** `{details['Last Usable IP']}`")
                
        elif details and "Error" in details:
             st.error(f"Invalid Subnet Format: {details['Error']}")
        else:
             st.error("Invalid Subnet Format")

def render_latency_analyzer():
    """
    Renders the HTTP Latency Analyzer view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Break down request timing into DNS, Connect, TTFB, and Transfer phases.")

    st.title("⏱️ HTTP Latency Analyzer")
    st.markdown("Analyze website performance and identify bottlenecks (TTFB).")
    
    url = st.text_input("Target URL", "https://www.google.com")
    
    if st.button("Analyze Latency"):
        if not url:
            st.warning("Please enter a URL.")
        else:
            with st.spinner(f"Measuring latency for {url}..."):
                metrics = analyze_latency(url)
                
                if metrics.get("Error"):
                    st.error(metrics["Error"])
                else:
                    # Metrics Row
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("DNS Lookup", f"{metrics['DNS Lookup']:.4f}s")
                    c2.metric("TCP Connect", f"{metrics['TCP Connection']:.4f}s")
                    c3.metric("TTFB", f"{metrics['TTFB']:.4f}s")
                    c4.metric("Download", f"{metrics['Content Download']:.4f}s")
                    
                    st.divider()
                    
                    # Total Time Alert
                    total_time = metrics['Total Time']
                    if total_time > 1.0:
                        st.warning(f"⚠️ High Latency Detected: Total Time {total_time:.4f}s (> 1.0s)")
                    else:
                        st.success(f"✅ Performance Optimal: Total Time {total_time:.4f}s")
                        
                    # Visualization
                    st.subheader("Latency Breakdown")
                    chart_data = pd.DataFrame({
                        "Phase": ["DNS Lookup", "TCP Connect", "TTFB", "Download"],
                        "Time (s)": [
                            metrics['DNS Lookup'],
                            metrics['TCP Connection'],
                            metrics['TTFB'],
                            metrics['Content Download']
                        ]
                    })
                    st.bar_chart(chart_data.set_index("Phase"), color="#FF4B4B")

def render_config_generator():
    """
    Renders the Config Generator view with inputs and tabbed outputs.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Generates consistent configs for Cisco NX-OS, Juniper Junos, and SONiC.")

    st.title("🏭 Config Generator")
    st.markdown("Automate interface and VLAN configurations.")

    with st.container(border=True):
        st.subheader("Input Parameters")
        col1, col2 = st.columns(2)
        
        with col1:
            interface_name = st.text_input("Interface Name", "Ethernet1/1", help="e.g. Ethernet1/1, ge-0/0/0")
            vlan_id = st.number_input("VLAN ID", min_value=1, max_value=4094, value=10)
            
        with col2:
            ip_address = st.text_input("IP Address/Mask", "192.168.10.1/24")
            mtu = st.number_input("MTU", min_value=576, max_value=9216, value=9000)

    if st.button("Generate Configs", type="primary"):
        data = {
            "interface_name": interface_name,
            "vlan_id": vlan_id,
            "ip_address": ip_address,
            "mtu": mtu
        }
        
        results = generate_configs(data)
        
        st.divider()
        st.subheader("Generated Configuration")
        
        tab1, tab2, tab3 = st.tabs(["Cisco NX-OS", "Juniper Junos", "Microsoft SONiC"])
        
        with tab1:
            st.code(results.get("Cisco NX-OS", ""), language="bash")
            st.write("Classic Datacenter CLI")
            
        with tab2:
            st.code(results.get("Juniper Junos", ""), language="bash")
            st.write("Structured Set Commands")
            
        with tab3:
            st.code(results.get("Microsoft SONiC", ""), language="json")
            st.write("JSON Format for ConfigDB")

            st.code(results.get("Microsoft SONiC", ""), language="json")
            st.write("JSON Format for ConfigDB")

def render_network_linter():
    """
    Renders the Network Linter view with textarea input and policy report.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Policy as Code: Automated validation against Golden Rules.")

    st.title("🛡️ Network Linter")
    st.markdown("Scan your configuration for Security, Performance, and Availability risks.")

    config_text = st.text_area("Paste Configuration", height=300, help="Paste standard CLI config (Cisco, Arista, etc)")

    if st.button("Run Policy Scan"):
        if not config_text.strip():
            st.warning("Please paste a configuration first.")
        else:
            with st.spinner("Running Unit Tests..."):
                results = lint_config(config_text)
                
            st.divider()
            st.subheader("Compliance Report")
            
            # Count errors
            errors = len([r for r in results if r['severity'] == 'Error'])
            warnings = len([r for r in results if r['severity'] == 'Warning'])
            passed = len([r for r in results if r['severity'] == 'Pass'])
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Errors (Critical)", errors, delta_color="inverse")
            c2.metric("Warnings", warnings, delta_color="inverse")
            c3.metric("Checks Passed", passed)
            
            st.markdown("### Detailed Findings")
            
            for item in results:
                if item['severity'] == "Error":
                    st.error(f"**{item['rule']}**: {item['message']}")
                elif item['severity'] == "Warning":
                    st.warning(f"**{item['rule']}**: {item['message']}")
                else:
                    st.success(f"**{item['rule']}**: {item['message']}")
                    

def render_route_optimizer():
    """
    Renders the Route Optimizer view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Algorithms: Uses IP Set Reduction to minimize CIDR blocks.")

    st.title("🧠 Route & ACL Optimizer")
    st.markdown("Summarize a list of IP addresses into the smallest possible set of CIDRs.")

    raw_text = st.text_area("Paste IP List (One per line)", height=300, help="e.g. 192.168.1.1, 10.0.0.0/24")

    if st.button("Optimize Routes", type="primary"):
        if not raw_text.strip():
            st.warning("Please paste some IP addresses.")
        else:
            with st.spinner("Optimizing using supernetting algorithms..."):
                results = optimize_routes(raw_text)
                
            st.divider()
            
            # Metrics
            c1, c2, c3 = st.columns(3)
            c1.metric("Original Count", results['original_count'])
            c2.metric("Optimized Count", results['optimized_count'])
            c3.metric("Optimization Ratio", f"{results['reduction_percentage']}%", delta_color="normal")
            
            if results['errors']:
                with st.expander("Parsing Errors (Ignored Lines)"):
                    st.write(results['errors'])
            
            st.subheader("Optimized CIDR List")
            st.code('\n'.join(results['optimized_cidrs']), language="text")
            st.caption("Copy this list for your Firewalls/ACLs.")

            st.subheader("Optimized CIDR List")
            st.code('\n'.join(results['optimized_cidrs']), language="text")
            st.caption("Copy this list for your Firewalls/ACLs.")

def render_topology_mapper():
    """
    Renders the LLDP Topology Mapper view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Visualizes 'show lldp neighbors' output as a network graph.")
        st.caption("Powered by Graphviz")

    st.title("🗺️ LLDP Topology Mapper")
    st.markdown("Visualize string connections from raw CLI output.")

    # Callback to load sample
    def load_cisco_sample():
        st.session_state.lldp_input = """
Device ID        Local Intf     Holdtme    Capability  Platform  Port ID
Switch-Core-01   Eth1/1         120        R B         N9K       Eth1/48
Router-Edge-02   Eth1/2         120        R           ASR       Gi0/0/1
Access-Switch-03 Eth1/3         120        S           Cat9k     Te1/0/48
Server-Rack-04   Eth1/4         120        H           Linux     eth0
        """.strip()

    # Two column layout: Input & Controls
    col1, col2 = st.columns([2, 1])

    with col2:
        st.subheader("Sample Data")
        st.button("Load Cisco Sample", on_click=load_cisco_sample)

    with col1:
        # Use value from session state if available
        lldp_input = st.text_area("Paste 'show lldp neighbors' output", height=300, key="lldp_input")
            
    if st.button("Visualize Topology", type="primary"):
        if not lldp_input.strip():
            st.warning("Please paste LLDP output.")
        else:
            try:
                dot_source = generate_topology_dot(lldp_input)
                st.divider()
                st.subheader("Network Graph")
                st.graphviz_chart(dot_source)
            except Exception as e:
                st.error(f"Visualization Error: {e}")



def render_bgp_inspector():
    """
    Renders the BGP Inspector view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Queries api.bgpview.io for ASN Details, Peers, and Prefixes.")
        st.caption("External Connectivity")

    st.title("🌎 BGP Looking Glass")
    st.markdown("Inspect Autonomous System (ASN) relationships and upstream providers.")

    asn_input = st.text_input("Enter ASN (Autonomous System Number)", "8075", help="e.g. 8075 (Microsoft), 15169 (Google)")

    if st.button("Inspect ASN", type="primary"):
        if not asn_input.isdigit():
            st.error("Please enter a valid numeric ASN.")
        else:
            with st.spinner(f"Fetching BGP data for AS{asn_input}..."):
                # 1. Get Details
                details = get_asn_details(asn_input)
                
                if "error" in details:
                    st.error(f"API Error: {details['error']}")
                else:
                    # Metrics
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Owner", details.get('owner', 'N/A'))
                    c2.metric("Country", details.get('country', 'N/A'))
                    c3.metric("RIR", details.get('rer', 'N/A'))
                    
                    # 2. Get Peers for Graph
                    peers = get_asn_peers(asn_input)
                    c4.metric("Total Peers", len(peers))
                    
                    st.divider()
                    
                    # Tabs for View
                    tab1, tab2 = st.tabs(["🕸️ Upstream Graph", "📋 Advertised Prefixes"])
                    
                    with tab1:
                        st.subheader("Upstream Connectivity Map")
                        if peers:
                             dot_source = generate_bgp_graph(asn_input, peers)
                             st.graphviz_chart(dot_source)
                        else:
                            st.warning("No peer data found.")
                            
                    with tab2:
                        st.subheader("Advertised IPv4 Prefixes")
                        prefixes = get_asn_prefixes(asn_input)
                        if prefixes:
                            df = pd.DataFrame(prefixes)
                            st.dataframe(df, use_container_width=True)
                        else:
                            st.info("No prefixes found.")

def render_home():
    """
    Renders the Home page with service tiles for navigation.
    """
    st.title("Network Automation Portal")
    st.markdown("Welcome to your central hub for network operations.")
    st.divider()
    
    # Row 1: 5 Columns
    cols = st.columns(5)
    
    # 1. Network Scanner
    with cols[0]:
        with st.container(border=True):
            st.write("📡")
            st.subheader("Network Scanner")
            st.write("Scan subnets to find devices, hostnames, and vendors.")
            if st.button("Launch Scanner", key="btn_launch_scanner", use_container_width=True):
                st.session_state['current_view'] = 'scanner'
                st.rerun()

    # 2. SSL Inspector
    with cols[1]:
        with st.container(border=True):
            st.write("🔐")
            st.subheader("SSL Inspector")
            st.write("Check bulk SSL certificates for expiry and validity.")
            if st.button("Launch Inspector", key="btn_launch_ssl", use_container_width=True):
                 st.session_state['current_view'] = 'ssl_inspector'
                 st.rerun()

    # 3. Config Diff
    with cols[2]:
        with st.container(border=True):
            st.write("⚖️")
            st.subheader("Config Diff")
            st.write("Compare configurations with side-by-side highlighting.")
            if st.button("Launch Comparator", key="btn_launch_diff", use_container_width=True):
                st.session_state['current_view'] = 'config_diff'
                st.rerun()

    # 4. Global DNS
    with cols[3]:
        with st.container(border=True):
            st.write("🌍")
            st.subheader("Global DNS")
            st.write("Check propagation across Google, Cloudflare, and Quad9.")
            if st.button("Launch DNS Checker", key="btn_launch_dns", use_container_width=True):
                st.session_state['current_view'] = 'dns_propagator'
                st.rerun()

    # 5. Subnet Calc
    with cols[4]:
        with st.container(border=True):
            st.write("🔢")
            st.subheader("Subnet Calc")
            st.write("Calculate CIDR masks, broadcast, and IP address ranges.")
            if st.button("Launch Calculator", key="btn_launch_subnet", use_container_width=True):
                st.session_state['current_view'] = 'subnet_calc'
                st.rerun()

    # Row 2: 5 Columns (to keep width consistent)
    st.write("") # Spacer
    cols_row2 = st.columns(5)
    
    # 6. Latency Analyzer (First column of second row)
    with cols_row2[0]:
        with st.container(border=True):
            st.write("⏱️")
            st.subheader("Latency Analyzer")
            st.write("Analyze DNS, TCP connect, TTFB, and download timings.")
            if st.button("Launch Analyzer", key="btn_launch_latency", use_container_width=True):
                st.session_state['current_view'] = 'latency_analyzer'
                st.rerun()

    # 7. Config Generator (Second column of second row)
    with cols_row2[1]:
        with st.container(border=True):
            st.write("🏭")
            st.subheader("Config Gen")
            st.write("Generate configs for Cisco, Juniper, and SONiC.")
            if st.button("Launch Generator", key="btn_launch_gen", use_container_width=True):
                st.session_state['current_view'] = 'config_gen'
                st.rerun()

    # 8. Network Linter (Third column of second row)
    with cols_row2[2]:
        with st.container(border=True):
            st.write("🛡️")
            st.subheader("Net Linter")
            st.write("Scan configs for Telnet, MTU, and disabled links.")
            if st.button("Launch Linter", key="btn_launch_linter", use_container_width=True):
                st.session_state['current_view'] = 'network_linter'
                st.rerun()

    # 9. Route Optimizer (Fourth column of second row)
    with cols_row2[3]:
         with st.container(border=True):
            st.write("🧠")
            st.subheader("Optimizer")
            st.write("Algorithmically summarize IPs into minimal CIDRs.")
            if st.button("Launch Optimizer", key="btn_launch_opt", use_container_width=True):
                st.session_state['current_view'] = 'route_optimizer'
                st.rerun()

    # 10. Topology Mapper (Fifth column of second row)
    with cols_row2[4]:
         with st.container(border=True):
            st.write("🗺️")
            st.subheader("Topology")
            st.write("Visualize LLDP neighbors as a graph.")
            if st.button("Launch Mapper", key="btn_launch_topo", use_container_width=True):
                st.session_state['current_view'] = 'topology_mapper'
                st.rerun()

    # 11. BGP Inspector (First column of third row - or actually let's re-flow)
    # To keep it balanced, let's just add a new row or squeeze it in.
    # Let's add a 3rd Row for "External" tools.
    
    st.write("")
    cols_row3 = st.columns(5)
    
    with cols_row3[0]:
         with st.container(border=True):
            st.write("🌎")
            st.subheader("BGP Look")
            st.write("Inspect ASN peers and prefixes.")
            if st.button("Launch BGP", key="btn_launch_bgp", use_container_width=True):
                st.session_state['current_view'] = 'bgp_inspector'
                st.rerun()

def render_network_scanner():
    """
    Renders the Network Scanner view, including sidebar controls, scanning logic, and results display.
    """
    # Sidebar for Scanning
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        
        st.header("New Scan")
        cidr_input = st.text_input("CIDR Block", "192.168.1.0/24")
        
        # Safety / Demo Mode
        demo_mode = st.checkbox("Demo Mode (Mask Data)", value=False)
        
        run_scan = st.button("Run Scan")
        
        st.divider()
        
        # Run History Panel
        st.subheader("Run History (Last 10)")
        history_list = load_history()
        if history_list:
            for item in history_list[:10]:
                label = f"{item['timestamp']} | {item['cidr']}"
                with st.expander(label):
                    st.write(f"Active: {item['active_count']}")
                    st.write(f"Duration: {item['duration']}s")
        else:
            st.write("No scan history.")

    # Main Layout
    st.header("Network Scanner")

    # Create a placeholder for the expander to ensure it's always in the same spot at the top
    log_expander = st.expander("Scan Logs (Errors/Warnings)", expanded=False)

    # Logic for running scan
    if run_scan:
        # Safety Check: Enforce /24 and Private IP unless explicitly ignored (which we won't allow in this version)
        if not is_private_cidr(cidr_input):
            st.error("Safety Violation: Only private IP ranges are allowed (e.g., 192.168.x.x, 10.x.x.x).")
            return 
            
        try:
            network_size = ipaddress.ip_network(cidr_input, strict=False).num_addresses
            if network_size > 256:
                st.error("Safety Violation: Maximum scan size is /24 (256 addresses).")
                return
        except ValueError:
            st.error("Invalid CIDR format.")
            return
        
        # Initialize/Clear session logs
        st.session_state['scan_logs'] = []
        
        # UI Elements for progress
        progress_bar = st.progress(0, text="Starting scan...")
        status_text = st.empty()
        
        # We need to write to the expander for logs
        with log_expander:
            log_placeholder = st.empty()
        
        def update_logs(msg):
            st.session_state['scan_logs'].append(msg)
            log_placeholder.code('\n'.join(st.session_state['scan_logs']))
            
        def update_progress(current, total):
            percent = min(1.0, current / total)
            progress_bar.progress(percent, text=f"Scanning: {current}/{total} IPs")

        with st.spinner(f"Scanning {cidr_input}..."):
            new_results, stats = scan_network(cidr_input, status_callback=update_logs, progress_callback=update_progress)
            
            # Store latest stats for summary
            st.session_state['last_scan_stats'] = stats
            
            # Log to History
            append_history(stats, cidr_input)

            # Load existing results to merge
            existing_df = load_data()
            if not existing_df.empty:
                # Convert to dict for easier merging by IP
                results_dict = existing_df.set_index('ip').to_dict('index')
            else:
                results_dict = {}

            # Merge new results
            for host in new_results:
                # host is a dict {'ip': ..., 'hostname': ..., 'mac': ..., 'vendor': ..., 'port_80': ..., 'ping': ...}
                ip = host['ip']
                # Remove ip key from dict
                data = host.copy()
                del data['ip']
                results_dict[ip] = data
                
            # Convert back to list
            merged_hosts = []
            for ip, data in results_dict.items():
                entry = {'ip': ip}
                entry.update(data)
                merged_hosts.append(entry)

            # Save results
            try:
                with open("scan_results.json", 'w') as f:
                    json.dump(merged_hosts, f, indent=4)
                st.success(f"Scan complete! Found {len(new_results)} active hosts.")
                st.rerun()
            except Exception as e:
                st.error(f"Error saving results: {e}")

    # Display Logs from Session State if we are NOT in the middle of a run
    elif 'scan_logs' in st.session_state and st.session_state['scan_logs']:
        with log_expander:
            st.code('\n'.join(st.session_state['scan_logs']))

    # Clear History Button
    if st.sidebar.button("Clear History"):
        try:
            with open("scan_results.json", 'w') as f:
                json.dump([], f)
            st.success("History cleared!")
            st.rerun()
        except Exception as e:
            st.error(f"Error clearing history: {e}")
            
    df = load_data()

    # Load data for display
    df = load_data()

    # Scan Summary Block
    if 'last_scan_stats' in st.session_state:
        stats = st.session_state['last_scan_stats']
        st.markdown("### Last Scan Summary")
        s1, s2, s3, s4, s5 = st.columns(5)
        s1.metric("Total Scanned", stats.get('total_scanned', 0))
        s2.metric("Duration", f"{stats.get('duration', 0):.2f}s")
        
        rate = stats.get('total_scanned', 0) / (stats.get('duration', 1) or 1)
        s3.metric("Rate (IPs/s)", f"{rate:.2f}")
        s4.metric("Active Hosts", stats.get('active_count', 0))
        s5.metric("Timeouts", stats.get('timeouts', 0))

    st.divider()

    # Results Table
    st.subheader("Active Hosts Found")
    
    if not df.empty:
        display_metrics(df)
        
        # Demo Mode Masking
        display_df = df.copy()
        if demo_mode: # Using the demo_mode checkbox from the sidebar
            display_df['ip'] = display_df['ip'].apply(lambda x: '***.***.***.' + x.split('.')[-1] if x else x)
            if 'mac' in display_df.columns:
                display_df['mac'] = display_df['mac'].apply(lambda x: str(x)[:8] + '**:**:**' if x and x != 'Unknown' else x)

        st.dataframe(
            display_df,
            column_config={
                "ip": "IP Address",
                "hostname": "Hostname",
                "mac": "MAC Address",
                "vendor": "Vendor",
                "port_80": st.column_config.CheckboxColumn("Port 80"),
                "ping": st.column_config.CheckboxColumn("Ping Reply"),
            },
            use_container_width=True
        )
        
        # Optional: Filter/Search
        st.markdown("### Search/Filter")
        search_term = st.text_input("Search IP")
        if search_term:
             filtered = display_df[display_df['ip'].astype(str).str.contains(search_term)]
             st.dataframe(filtered)
    else:
        st.info("No active hosts found yet. Try running a scan!")

    # Display Logs from Session State if we are NOT in the middle of a run
    if 'scan_logs' in st.session_state and st.session_state['scan_logs']:
        with log_expander:
            st.code('\n'.join(st.session_state['scan_logs']))

def render_floating_ai_assistant():
    """
    Renders the AI Assistant as a floating chat icon in the bottom right.
    """
    # CSS to float the popover button
    st.markdown("""
    <style>
    /* Float the specific popover container */
    [data-testid="stPopover"] {
        position: fixed !important;
        bottom: 30px !important;
        right: 30px !important;
        z-index: 10000 !important;
    }
    /* Style the button circle */
    [data-testid="stPopover"] > div > button {
        width: 70px !important;
        height: 70px !important;
        border-radius: 50% !important;
        background-color: #FF4B4B !important;
        color: white !important;
        border: none !important;
        box-shadow: 0px 4px 15px rgba(0,0,0,0.3) !important;
        font-size: 30px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
    }
    /* Hide the default caret */
    [data-testid="stPopover"] > div > button span {
        display: none !important;
    }
    /* Tooltip/Hover effect */
    [data-testid="stPopover"] > div > button:hover {
        transform: scale(1.1);
        transition: transform 0.2s;
    }
    </style>
    """, unsafe_allow_html=True)

    # Popover Chat Interface
    with st.popover("🤖", help="AI Network Assistant"):
        st.subheader("Network Assistant")
        st.caption("Powered by NVIDIA Nemotron")
        
        # Chat History Container
        messages_container = st.container(height=400)
        
        # Initialize History
        if "messages" not in st.session_state:
            st.session_state["messages"] = [{"role": "assistant", "content": "Hello! I'm your Network Engineer AI. How can I help you today?"}]

        # Display History
        with messages_container:
            for msg in st.session_state.messages:
                st.chat_message(msg["role"]).write(msg["content"])

        # Chat Input (Inside Popover)
        if prompt := st.chat_input("Ask about subnets, DNS, configs...", key="chat_input_popover"):
            st.session_state.messages.append({"role": "user", "content": prompt})
            messages_container.chat_message("user").write(prompt)
            
            with messages_container.chat_message("assistant"):
                with st.spinner("Analyzing..."):
                    response = get_ai_response(prompt)
                    st.write(response)
            
            st.session_state.messages.append({"role": "assistant", "content": response})

def main():
    # Page Config must be the first Streamlit command
    st.set_page_config(
        page_title="Network Automation Portal",
        page_icon="📡",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize session state for navigation
    if 'current_view' not in st.session_state:
        st.session_state['current_view'] = 'home'
        
    # Render the appropriate view
    if st.session_state['current_view'] == 'home':
        render_home()
    elif st.session_state['current_view'] == 'scanner':
        render_network_scanner()
    elif st.session_state['current_view'] == 'ssl_inspector':
        render_ssl_inspector()
    elif st.session_state['current_view'] == 'config_diff':
        render_config_comparator()
    elif st.session_state['current_view'] == 'dns_propagator':
        render_dns_propagator()
    elif st.session_state['current_view'] == 'subnet_calc':
        render_subnet_calculator()
    elif st.session_state['current_view'] == 'latency_analyzer':
        render_latency_analyzer()
    elif st.session_state['current_view'] == 'config_gen':
        render_config_generator()
    elif st.session_state['current_view'] == 'network_linter':
        render_network_linter()
    elif st.session_state['current_view'] == 'route_optimizer':
        render_route_optimizer()
    elif st.session_state['current_view'] == 'topology_mapper':
        render_topology_mapper()
    elif st.session_state['current_view'] == 'bgp_inspector':
        render_bgp_inspector()
        
    # Global Features
    render_floating_ai_assistant()

if __name__ == "__main__":
    main()
