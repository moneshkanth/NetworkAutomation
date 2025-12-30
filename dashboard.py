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
from config_generator import generate_configs, generate_bulk_configs
from network_linter import lint_config
from route_optimizer import optimize_routes
from topology_mapper import generate_topology_dot
from bgp_inspector import get_asn_details, get_asn_peers, get_asn_prefixes, generate_bgp_graph
from mac_inspector import get_mac_vendor
from log_extractor import extract_patterns
from tcp_calculator import calculate_tcp_performance
from tcp_calculator import calculate_tcp_performance
from azure_ranger import fetch_azure_data_v2, get_unique_regions, filter_azure_ranges, generate_cisco_acl
from recon_tools import get_shodan_data, get_crt_subdomains
from recon_tools import get_shodan_data, get_crt_subdomains
from recon_tools import get_shodan_data, get_crt_subdomains
from recon_tools import get_shodan_data, get_crt_subdomains
from zerossl_manager import list_certificates, get_certificate_download_link, create_certificate, generate_key_and_csr
from vlsm_calculator import calculate_vlsm, get_free_space_summary
from utility_tools import calculate_azure_egress, convert_optical_power, exclude_subnets, calculate_mtu_overhead
from config_sanitizer import sanitize_config

def render_config_sanitizer():
    """Renders the Configuration Sanitizer page."""
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Redact sensitive info like passwords, public IPs, and MACs.")

    st.title("🧹 Configuration Sanitizer")
    st.markdown("Scrub sensitive data from your configuration files before sharing.")

    # Input Area
    raw_text = st.text_area("Raw Configuration/Log", height=200)

    # Options
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        redact_passwords_opt = st.checkbox("Remove Passwords/Secrets", value=True)
    with col2:
        # Public IPs only (keep 10.x, 192.168.x)
        redact_public_ips_opt = st.checkbox("Remove Public IPs")
    with col3:
        redact_macs_opt = st.checkbox("Remove MAC Addresses")
    with col4:
        redact_snmp_opt = st.checkbox("Remove SNMP Strings")

    if st.button("Sanitize Config", type="primary"):
        if not raw_text:
            st.warning("Please enter some text to sanitize.")
        else:
            options = {
                "passwords": redact_passwords_opt,
                "public_ips": redact_public_ips_opt,
                "mac_addresses": redact_macs_opt,
                "snmp": redact_snmp_opt
            }
            
            clean_text = sanitize_config(raw_text, options)
            
            st.divider()
            
            # Side-by-Side Diff
            st.subheader("Changes Made (Diff)")
            # Reusing generate_html_diff from config_diff import which is already imported
            html_diff = generate_html_diff(raw_text, clean_text)
            if html_diff:
                 st.components.v1.html(html_diff, height=400, scrolling=True)
            else:
                 st.info("No sensitive data found matching selected filters.")
            
            st.subheader("Clean Configuration")
            st.text_area("Copy Clean Config", value=clean_text, height=200)
            
            # Download button for convenience?
            st.download_button("Download Clean Config", clean_text, file_name="sanitized_config.txt")


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

from config_sanitizer import sanitize_config
from voip_calculator import calculate_voip_bandwidth, calculate_video_bandwidth

def render_voip_calculator():
    """Renders the VoIP & Video Bandwidth Calculator."""
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Plan bandwidth for Voice (VoIP) and Video Conferencing.")

    st.title("📞 VoIP & Video Bandwidth Planner")
    st.markdown("Estimate WAN capacity requirements including critical protocol overheads.")

    tab1, tab2 = st.tabs(["🎙️ Voice (VoIP)", "📹 Video Conferencing"])

    with tab1:
        c1, c2 = st.columns(2)
        with c1:
             num_calls = st.slider("Number of Concurrent Calls", 1, 1000, 100)
             codec = st.selectbox("Codec", ["G.711 (64kbps)", "G.729 (8kbps)", "Opus (Wideband)"])
        
        with c2:
             st.subheader("Overhead Options")
             include_l2 = st.checkbox("Include Layer 2 (Ethernet) Header", value=True, help="Adds 38 bytes (Header+FCS+Preamble+IPG)")
             use_vpn = st.checkbox("Include IPSec VPN Overhead", value=False, help="Adds ~50 bytes for ESP/Tunneling")
             c_rtp = st.checkbox("Use cRTP (Compressed RTP)", value=False, help="Reduces IP/UDP/RTP from 40B to ~4B")

        if st.button("Calculate VoIP Bandwidth", type="primary"):
            results = calculate_voip_bandwidth(num_calls, codec, include_l2, use_vpn, c_rtp)
            
            st.divider()
            
            # Big Metrics
            m1, m2, m3 = st.columns(3)
            m1.metric("Total Bandwidth", f"{results['total_bandwidth_mbps']:.2f} Mbps")
            m2.metric("Total PPS", f"{results['pps']:,.0f}")
            m3.metric("Bandwidth per Call", f"{results['bandwidth_bps_per_call']/1000:.1f} kbps")
            
            # Comparison Chart (Payload vs Overhead)
            st.subheader("Packet Composition (Bytes)")
            breakdown = results['breakdown']
            chart_df = pd.DataFrame([breakdown])
            st.bar_chart(chart_df, color=["#36a2eb", "#ff6384", "#4bc0c0", "#ff9f40"])
            
            st.caption("Notice how much overhead (L2/L3) adds compared to the actual Voice Payload, especially for G.729!")

    with tab2:
        c1, c2 = st.columns(2)
        with c1:
            vid_calls = st.slider("Concurrent Video Sessions", 1, 100, 10)
        with c2:
            quality = st.selectbox("Video Quality", ["720p HD", "1080p FHD", "4K UHD", "Standard (480p)"])
            
        if st.button("Calculate Video Bandwidth"):
            v_res = calculate_video_bandwidth(vid_calls, quality)
            
            st.divider()
            st.metric("Total Video Bandwidth", f"{v_res['total_bandwidth_mbps']:.2f} Mbps")
            st.info(f"Assuming ~{v_res['per_call_mbps']} Mbps per stream.")

from ipv6_master import analyze_ipv6

def render_ipv6_master():
    """Renders the IPv6 Master Tool."""
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Expand, Compress, and Analyze IPv6 Addresses.")

    st.title("🌐 IPv6 Master Tool")
    st.markdown("Demystify the 128-bit address space.")

    # Input
    ipv6_input = st.text_input("Enter IPv6 Address", "2001:db8::1", help="e.g. 2001:db8::1, fe80::1")

    if ipv6_input:
        result = analyze_ipv6(ipv6_input)
        
        if "error" in result:
             st.error(f"❌ {result['error']}")
        else:
             st.success("✅ Valid IPv6 Address")
             st.divider()
             
             # Main Card
             with st.container(border=True):
                 c1, c2 = st.columns(2)
                 with c1:
                     st.write("**Address Type**")
                     st.subheader(f"🏷️ {result['type']}")
                 with c2:
                      st.write("**Description**")
                      st.info(result['description'])
             
             st.divider()
             
             # Formats
             st.subheader("Formats")
             
             st.caption("Compressed (Canonical)")
             st.code(result['compressed'], language='text')
             
             st.caption("Exploded (Full 32 Hex Characters)")
             st.code(result['exploded'], language='text')
             
             # Details
             with st.expander("Technical Details"):
                 st.write(f"**Multicast:** {result['is_multicast']}")
                 st.write(f"**Private (Unique Local):** {result['is_private']}")
                 st.write(f"**Global Unicast:** {result['is_global']}")
                 st.write(f"**Link-Local:** {result['is_link_local']}")
                 st.write(f"**Loopback:** {result['is_loopback']}")

from log_cost_estimator import calculate_log_cost

def render_log_cost_estimator():
    """Renders the Log Storage & Observability Cost Estimator."""
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Estimate Monthly Bills for Datadog, Splunk, or S3 Logging.")

    st.title("💸 Log Cost Estimator")
    st.markdown("Avoid sticker shock by estimating observability costs.")

    # Tiers
    tiers = {
        "SaaS Enterprise (High Ingest)": {"ingestion_rate": 2.50, "storage_rate": 0.10, "included_retention": 7, "name": "SaaS Enterprise"},
        "SaaS Standard (Datadog/NewRelic avg)": {"ingestion_rate": 1.70, "storage_rate": 0.10, "included_retention": 7, "name": "SaaS Standard"},
        "DIY / Cloud Storage (S3 Standard)": {"ingestion_rate": 0.00, "storage_rate": 0.023, "included_retention": 0, "name": "AWS S3 Standard"},
        "DIY / High Performance (EBS/SSD)": {"ingestion_rate": 0.00, "storage_rate": 0.10, "included_retention": 0, "name": "Self-Hosted SSD"},
    }
    
    col_config, col_results = st.columns([1, 1])
    
    with col_config:
        st.subheader("Parameters")
        tier_name = st.selectbox("Pricing Model", list(tiers.keys()))
        selected_tier = tiers[tier_name]
        
        daily_gb = st.slider("Daily Ingestion (GB)", 1, 5000, 100)
        retention_days = st.select_slider("Retention Period (Days)", options=[7, 14, 30, 60, 90, 180, 365, 730], value=30)
        
        st.caption(f"**Rate Info:** Ingest ${selected_tier['ingestion_rate']}/GB, Storage ${selected_tier['storage_rate']}/GB/mo")

    with col_results:
        st.subheader("Estimated Monthly Cost")
        
        # Calculation
        res = calculate_log_cost(daily_gb, retention_days, selected_tier)
        
        # Big metric
        st.metric("Total Monthly Bill", f"${res['total_monthly_cost']:,.2f}")
        
        c1, c2 = st.columns(2)
        c1.metric("Ingestion Cost", f"${res['ingestion_cost']:,.2f}")
        c2.metric("Storage Cost", f"${res['storage_cost']:,.2f}")
        
        # Chart
        chart_data = pd.DataFrame([
            {"Category": "Ingestion", "Cost": res['ingestion_cost']},
            {"Category": "Storage", "Cost": res['storage_cost']}
        ])
        st.bar_chart(chart_data.set_index("Category"))
        
        if res['total_monthly_cost'] > 10000:
             st.warning("⚠️ High Cost Alert! Consider moving old logs to Cold Storage (S3 Glacier).")

from disk_calculator import calculate_disk_performance

def render_disk_calculator():
    """Renders the Cloud Disk Performance Calculator."""
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Simulate AWS GP3 and Azure Premium SSD performance limitations.")

    st.title("💾 Cloud Disk Performance")
    st.markdown("Avoid throttling by sizing your disks correctly.")

    col1, col2 = st.columns(2)
    
    with col1:
        provider = st.selectbox("Cloud Provider / Disk Type", ["AWS GP3", "Azure Premium SSD"])
        
    with col2:
        size = st.number_input("Disk Size (GB)", min_value=1, max_value=32768, value=128, step=10)

    if st.button("Calculate Limits"):
        res = calculate_disk_performance(size, provider)
        
        st.divider()
        st.subheader("Performance Limits")
        
        m1, m2 = st.columns(2)
        m1.metric("Max IOPS", f"{res['iops']:,}")
        m2.metric("Max Throughput", f"{res['throughput_mbps']} MB/s")
        
        if res['notes']:
            st.info(f"ℹ️ {res['notes']}")
        
        # Visual Gauge (using progress bar as simple linear gauge)
        st.write("IOPS Utilization Visual (Scale: 0 - 20,000)")
        iops_norm = min(res['iops'] / 20000, 1.0)
        st.progress(iops_norm)
        
        st.write("Throughput Utilization Visual (Scale: 0 - 1,000 MB/s)")
        through_norm = min(res['throughput_mbps'] / 1000, 1.0)
        st.progress(through_norm)

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



def render_mac_inspector():
    """
    Renders the MAC Vendor Inspector view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Queries api.macvendors.com for manufacturer details.")
    
    st.title("🏷️ MAC Vendor Inspector")
    st.markdown("Identify the manufacturer of a network device from its MAC address.")

    # Centered Layout
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        mac_input = st.text_input("Enter MAC Address", placeholder="e.g. 00:1A:2B:3C:4D:5E")
        
        if st.button("Find Vendor", type="primary", use_container_width=True):
            if not mac_input:
                st.warning("Please enter a MAC address.")
            else:
                with st.spinner("Querying OUI Database..."):
                    result = get_mac_vendor(mac_input)
                    
                    st.divider()
                    
                    if "error" in result:
                        st.error(result['error'])
                    else:
                        st.success(f"**Vendor Found:**")
                        st.markdown(f"### {result['vendor']}")
                        st.balloons()


def render_log_extractor():
    """
    Renders the Log Pattern Extractor view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Extracts IOCs (IPs, Emails) and Errors from unstructured text.")

    st.title("📂 Log Pattern Extractor")
    st.markdown("Parse chaos into structured data.")

    # Controls
    mode = st.selectbox("Extraction Mode", ["IPv4", "Email", "Errors"])
    
    log_text = st.text_area("Paste Log Data", height=300, help="Paste syslog, server logs, or any text blob.")
    
    if st.button("Extract Patterns", type="primary"):
        if not log_text.strip():
            st.warning("Please paste some text.")
        else:
            with st.spinner("Parsing patterns..."):
                result = extract_patterns(log_text, mode)
                
                st.divider()
                
                if "error" in result:
                    st.error(result['error'])
                else:
                    count = result['count']
                    data = result['results']
                    
                    st.metric(f"Found ({mode})", count)
                    
                    if count > 0:
                        st.subheader("Results")
                        # For Errors (lines), just show text list
                        if mode == "Errors":
                             for line in data:
                                 st.code(line, language="text")
                        else:
                             # For IPs/Emails, dataframe is nice
                             df = pd.DataFrame(data, columns=["Match"])
                             st.dataframe(df, use_container_width=True)
                    else:
                        st.info("No matches found.")



def render_tcp_calculator():
    """
    Renders the TCP Performance Calculator view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Calculates Bandwidth Delay Product (BDP) and TCP Window limits.")

    st.title("🧮 TCP Performance Calculator")
    st.markdown("Optimize throughput for high-BDP links.")

    with st.container(border=True):
        st.subheader("Link Parameters")
        col1, col2, col3 = st.columns([1, 1, 2])
        
        with col1:
            bandwidth = st.number_input("Bandwidth", min_value=1.0, value=1.0, step=0.5)
        with col2:
            unit = st.selectbox("Unit", ["Gbps", "Mbps"])
        with col3:
            rtt = st.slider("Round Trip Time (ms)", min_value=0, max_value=500, value=50, step=1)

    if st.button("Calculate Performance", type="primary"):
        results = calculate_tcp_performance(bandwidth, unit, rtt)
        
        if "error" in results:
            st.error(results['error'])
        else:
            st.divider()
            
            # Key Metric: BDP (Required Window)
            st.success(f"### Required Window Size: **{results['optimal_window_size']}**")
            st.caption("To fill this pipe, your TCP buffers must be at least this size.")
            
            # Throughput Details
            c1, c2, c3 = st.columns(3)
            c1.metric("Link Capacity", f"{results['link_capacity_mbps']} Mbps")
            c2.metric("Max Speed (64KB Wind)", f"{results['standard_window_throughput_mbps']} Mbps")
            c3.metric("Efficiency Drop", f"{100 - results['efficiency']:.1f}%", delta_color="inverse")
            
            # Warning if efficient is low
            if results['efficiency'] < 50:
                st.warning(f"⚠️ High Latency Impact: With a standard 64KB window, you are only utilizing {results['efficiency']}% of your link.")
                st.info("💡 **Recommendation**: Enable TCP Window Scaling (RFC 1323) on your OS.")
            else:
                st.success("✅ Good Performance: Standard TCP settings are sufficient for this latency.")
            
            # Visualization
            st.subheader("Throughput Comparison")
            chart_data = pd.DataFrame({
                "Default Window (64KB)": [results['standard_window_throughput_mbps']],
                "Optimized Window": [results['link_capacity_mbps']]
            })
            st.bar_chart(chart_data, color=["#FFCDD2", "#A5D6A7"])

def render_azure_ranger():
    """
    Renders the Azure Service Tag Explorer view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Fetches live Service Tags from Microsoft. Cached for performance.")

    st.title("☁️ Azure Service Tag Explorer")
    st.markdown("Generate Firewall ACLs dynamically from Microsoft's public cloud data.")

    # 1. Fetch Data
    with st.spinner("Fetching Azure Data (this may take a moment)..."):
        data = fetch_azure_data_v2()
        
    if "error" in data:
        st.error(f"Failed to fetch data: {data['error']}")
        return

    # 2. Extract Regions for Dropdown
    regions = get_unique_regions(data)
    regions.insert(0, "All")

    # 3. Controls
    # Initialize session state for search
    if 'azure_search_q' not in st.session_state:
        st.session_state.azure_search_q = ""

    st.caption("Common Services:")
    b_cols = st.columns(6)
    quick_picks = ["AzureDevOps", "Sql", "Storage", "AppService", "AzureCloud", "LogicApps"]
    for i, svc in enumerate(quick_picks):
        if b_cols[i].button(svc, use_container_width=True):
             st.session_state.azure_search_q = svc
             st.rerun()

    col1, col2 = st.columns(2)
    with col1:
        service_query = st.text_input("Search Service", placeholder="e.g. AzureDevOps, Sql, Storage", key="azure_search_q")
    with col2:
        region_filter = st.selectbox("Filter Region", regions, index=0)

    # 4. Process
    if service_query:
        matches = filter_azure_ranges(data, service_query, region_filter)
        count = len(matches)
        
        st.divider()
        st.subheader("Results")
        st.metric("Total IPv4 Ranges Found", count)
        
        if count > 0:
            # Generate ACL
            acl_text = generate_cisco_acl(matches)
            
            tab1, tab2 = st.tabs(["📜 Cisco ACL", "📋 Raw List"])
            
            with tab1:
                st.code(acl_text, language="text")
                st.caption("Copy this into your firewall configuration.")
            
            with tab2:
                st.text_area("IP List", "\n".join(matches), height=200)
                
            # Download Button
            st.download_button(
                label="Download ACL (.txt)",
                data=acl_text,
                file_name=f"azure_acl_{service_query}_{region_filter}.txt",
                mime="text/plain"
            )
        else:
             st.warning("No matching IP ranges found. Try a different service name or region.")
    else:
        st.info("Start by typing a service name above (e.g. 'AzureDevOps').")

def render_shodan_scanner():
    """
    Renders the Shodan Public Attack Surface view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Uses Shodan InternetDB to scan public IPs without touching them.")

    st.title("🛡️ Public Attack Surface Scanner")
    st.markdown("Instantly see what hackers see. Powered by **Shodan**.")

    # Initialize session state for IP
    if 'shodan_ip_q' not in st.session_state:
        st.session_state.shodan_ip_q = "1.1.1.1"

    st.caption("Try a target:")
    b_cols = st.columns(6)
    if b_cols[0].button("Cloudflare", use_container_width=True):
        st.session_state.shodan_ip_q = "1.1.1.1"
        st.rerun()
    if b_cols[1].button("Google DNS", use_container_width=True):
        st.session_state.shodan_ip_q = "8.8.8.8"
        st.rerun()
    if b_cols[2].button("Quad9", use_container_width=True):
        st.session_state.shodan_ip_q = "9.9.9.9"
        st.rerun()

    ip_address = st.text_input("Enter Public IP Address", key="shodan_ip_q")
    
    if st.button("Scan IP", type="primary"):
        if not ip_address:
            st.warning("Please enter a valid IP address.")
            return

        with st.spinner(f"Scanning {ip_address}..."):
            data = get_shodan_data(ip_address)
            
        if "error" in data:
            st.error(data['error'])
        else:
            st.divider()
            
            # Key Info
            c1, c2, c3 = st.columns(3)
            c1.metric("IP", data.get('ip', 'N/A'))
            c2.metric("Hostnames", ", ".join(data.get('hostnames', [])) or "None")
            c3.metric("Open Ports", len(data.get('ports', [])))
            
            # Tags
            tags = data.get('tags', [])
            if tags:
                st.write("**Tags:**")
                st.write(" ".join([f"`{t}`" for t in tags]))
            
            st.divider()

            # Enhanced Port Visualization
            st.subheader("Open Port Analysis")
            ports = data.get('ports', [])
            
            if ports:
                # Port Mapping
                port_service_map = {
                    21: ("FTP", "File Transfer"), 22: ("SSH", "Secure Shell"), 23: ("Telnet", "Unencrypted Remote"),
                    25: ("SMTP", "Email"), 53: ("DNS", "Domain Name"), 80: ("HTTP", "Web"),
                    110: ("POP3", "Email"), 143: ("IMAP", "Email"), 389: ("LDAP", "Directory"),
                    443: ("HTTPS", "Secure Web"), 445: ("SMB", "Windows Share"), 3306: ("MySQL", "Database"),
                    3389: ("RDP", "Remote Desktop"), 5432: ("PostgreSQL", "Database"), 6379: ("Redis", "Database"),
                    8080: ("HTTP-Alt", "Web Alt"), 8443: ("HTTPS-Alt", "Secure Web Alt")
                }
                
                # Buckets
                critical_ports = []
                web_ports = []
                other_ports = []
                
                for p in ports:
                    if p in [21, 23, 3389, 445]: # High Risk
                        critical_ports.append(p)
                    elif p in [80, 443, 8080, 8443]:
                        web_ports.append(p)
                    else:
                        other_ports.append(p)

                # Visuals
                if critical_ports:
                    with st.container(border=True):
                        st.error("🚨 **CRITICAL EXPOSURE DETECTED**")
                        cols = st.columns(4)
                        for i, p in enumerate(critical_ports):
                            svc, desc = port_service_map.get(p, ("Unknown", "Service"))
                            with cols[i % 4]:
                                st.metric(f"Port {p}", svc, desc, delta_color="inverse")
                        st.caption("These ports should almost NEVER be open to the public internet.")

                if web_ports:
                    with st.container(border=True):
                        st.success("🌐 **Web Services**")
                        cols = st.columns(4)
                        for i, p in enumerate(web_ports):
                            svc, desc = port_service_map.get(p, ("Web", "Service"))
                            with cols[i % 4]:
                                st.metric(f"Port {p}", svc, desc)

                if other_ports:
                    with st.expander("🔵 Other Open Ports", expanded=True):
                        cols = st.columns(6)
                        for i, p in enumerate(other_ports):
                            svc, desc = port_service_map.get(p, ("Generic", "TCP"))
                            with cols[i % 6]:
                                st.markdown(f"**{p}**<br><span style='font-size:0.8em; color:gray'>{svc}</span>", unsafe_allow_html=True)

            else:
                 st.success("✅ **Clean Scan**: No open ports detected by Shodan.")

            # Vulns
            vulns = data.get('vulns', [])
            if vulns:
                st.subheader(f"⚠️ Vulnerabilities ({len(vulns)})")
                with st.expander("View CVE List", expanded=True):
                    # Format as a grid of badges
                    vuln_badges = [f"**{v}**" for v in vulns]
                    st.write(", ".join(vuln_badges))
            else:
                st.info("✅ No CVEs linked to this IP in Shodan's database.")

def render_zerossl_manager():
    """
    Renders the ZeroSSL Lifecycle Manager view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Manage your ZeroSSL Certificates via API.")
    
    st.title("🔐 ZeroSSL Lifecycle Manager")
    st.markdown("Automate your certificate inventory. Connects to **ZeroSSL API**.")

    # API Key Input (Pre-filled with user provided key for convenience)
    if 'zerossl_api_key' not in st.session_state:
        st.session_state.zerossl_api_key = "8d61b731d206e2f9d088c28c155b45dc"
        
    api_key = st.text_input("ZeroSSL API Key", value=st.session_state.zerossl_api_key, type="password")
    
    if st.button("Fetch Inventory", type="primary"):
        if not api_key:
            st.warning("Please enter your API Key.")
        else:
            st.session_state['zerossl_fetch_trigger'] = True

    # Tabs for organization
    tab1, tab2 = st.tabs(["📋 Inventory", "➕ Create Certificate"])

    with tab1:
        if st.session_state.get('zerossl_fetch_trigger'):
             with st.spinner("Fetching certificates from ZeroSSL..."):
                certs = list_certificates(api_key)
                
             if isinstance(certs, dict) and "error" in certs:
                st.error(f"API Error: {certs['error']}")
             else:
                st.session_state.zerossl_api_key = api_key # Persist valid key
                
                count = len(certs)
                st.success(f"Found {count} certificates.")
                st.divider()
                
                if count == 0:
                    st.info("No certificates found in this account.")
                else:
                    # Prepare display data
                    display_data = []
                    for c in certs:
                        display_data.append({
                            "Domain": c.get('common_name', 'Unknown'),
                            "Status": c.get('status', 'unknown'),
                            "Expires": c.get('expires', 'N/A'),
                            "ID": c.get('id')
                        })
                    
                    # Render Cards
                    for item in display_data:
                        with st.container(border=True):
                            c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
                            with c1:
                                st.subheader(item['Domain'])
                                st.caption(f"ID: {item['ID']}")
                            with c2:
                                status = item['Status']
                                if status == 'issued': st.success(f"✅ {status.upper()}")
                                elif status == 'pending_validation': st.warning(f"⏳ {status.upper()}")
                                elif status in ['expired', 'cancelled', 'revoked']: st.error(f"🔴 {status.upper()}")
                                else: st.info(f"{status.upper()}")
                            with c3:
                                st.write(f"**Expires:** {item['Expires']}")
                            with c4:
                                if item['Status'] == 'issued':
                                    st.write("📥 Ready")
                                else:
                                    st.write("---")

    with tab2:
        st.subheader("Issue New Certificate")
        st.info("Create a new 90-Day Certificate via ZeroSSL.")
        
        # Initialize session state for the newly created key if not present
        if 'zerossl_new_key' not in st.session_state:
            st.session_state.zerossl_new_key = None
            st.session_state.zerossl_new_csr = None
            st.session_state.zerossl_last_res = None
            st.session_state.zerossl_last_domain = None

        with st.form("create_cert_form"):
            domains_input = st.text_input("Domain Name(s)", placeholder="example.com, www.example.com")
            csr_input = st.text_area("CSR (Certificate Signing Request) - Optional", placeholder="-----BEGIN CERTIFICATE REQUEST-----...", height=150)
            validity = st.selectbox("Validity", ["90 Days"], disabled=True)
            
            submitted = st.form_submit_button("Create Certificate")
            
        if submitted:
            if not domains_input:
                st.error("Please enter at least one domain.")
            elif not api_key:
                st.error("Please enter your API Key above.")
            else:
                with st.spinner("Communicating with ZeroSSL Authority..."):
                    # Clean domains
                    domains = domains_input.replace(" ", "")
                    
                    # Validate/Sanitize CSR
                    final_csr = None
                    generated_private_key = None
                    
                    if csr_input and len(csr_input.strip()) > 10 and "-----BEGIN" in csr_input:
                        final_csr = csr_input.strip()
                    else:
                        st.info("Generating 2048-bit RSA Key & CSR locally...")
                        try:
                            common_name = domains.split(',')[0].strip()
                            generated_private_key, final_csr = generate_key_and_csr(common_name)
                        except Exception as e:
                            st.error(f"Failed to generate CSR: {e}")
                            st.stop()

                    res = create_certificate(api_key, domains, csr=final_csr)
                    
                    if "error" in res:
                        err_type = res['error']
                        if err_type == "certificate_limit_reached":
                             st.error("🛑 Free Plan Limit Reached")
                             st.warning("Your ZeroSSL account has reached its 90-day certificate limit (usually 3).")
                             st.info("💡 Tip: Use a different API Key or upgrade your ZeroSSL plan.")
                        else:
                             st.error(f"Creation Failed: {err_type}")
                        
                        if "details" in res:
                            with st.expander("Debug Details"):
                                st.json(res['details'])
                    else:
                        # Success! Save to session state to display outside form
                        st.session_state.zerossl_new_key = generated_private_key
                        st.session_state.zerossl_new_csr = final_csr
                        st.session_state.zerossl_last_res = res
                        st.session_state.zerossl_last_domain = domains.split(',')[0]
                        st.rerun() # Rerun to show results below

        # Display Result (Outside Form)
        if st.session_state.zerossl_last_res:
             res = st.session_state.zerossl_last_res
             st.divider()
             st.balloons()
             st.success(f"Certificate Created Successfully! ID: {res.get('id')}")
             
             # Show Private Key if we generated it
             if st.session_state.zerossl_new_key:
                 st.warning("⚠️ **IMPORTANT**: Save this Private Key! It is not stored in ZeroSSL.")
                 priv_key = st.session_state.zerossl_new_key
                 st.code(priv_key, language="text")
                 st.download_button("Download Private Key (.key)", priv_key, file_name=f"{st.session_state.zerossl_last_domain}.key")
             
             with st.expander("Raw API Response"):
                 st.json(res)
             
             st.info("Navigate to Inventory to see status or complete validation.")
             
             if st.button("Clear Results"):
                 st.session_state.zerossl_new_key = None
                 st.session_state.zerossl_last_res = None
                 st.rerun()

def render_vlsm_architect():
    """
    Renders the VLSM Subnet Architect view.
    """
    with st.sidebar:
        if st.button("← Back to Home"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Recursive VLSM Allocation.")
        st.write("1. Inputs Root Network.")
        st.write("2. Inputs Requirements.")
        st.write("3. Sorts & Allocates.")
    
    st.title("📐 VLSM Subnet Architect")
    st.markdown("Automated Variable Length Subnet Masking calculator. Allocates subnets based on host requirements.")
    
    # 1. Root Network Input
    c1, c2 = st.columns([2, 1])
    with c1:
        root_cidr = st.text_input("Root Network (CIDR)", "192.168.0.0/24")
    
    st.divider()
    
    # 2. Dynamic Requirements Input
    st.subheader("Subnet Requirements")
    st.caption("Add rows for each VLAN/Subnet you need.")
    
    if 'vlsm_reqs' not in st.session_state:
        # Default starting data
        st.session_state.vlsm_reqs = pd.DataFrame([
            {"Subnet Name": "VLAN_HR", "Hosts Needed": 50},
            {"Subnet Name": "VLAN_Dev", "Hosts Needed": 12},
            {"Subnet Name": "VLAN_Mgmt", "Hosts Needed": 5},
        ])

    # CONFIG: Data Editor for interactive table
    edited_df = st.data_editor(
        st.session_state.vlsm_reqs,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Subnet Name": st.column_config.TextColumn("Subnet Name", required=True),
            "Hosts Needed": st.column_config.NumberColumn("Hosts Needed", min_value=1, max_value=100000, required=True, step=1)
        },
        key="vlsm_editor"
    )
    
    if st.button("Calculate Allocation", type="primary"):
        # Convert Editor Data to List of Dicts
        requirements = edited_df.to_dict(orient="records")
        
        # Clean keys to match expected logic (The editor keys match display, so we map them if needed)
        # Our logic expects 'name' and 'hosts', or we update logic to use specific keys.
        # Let's map strict keys for the function
        mapped_reqs = []
        for r in requirements:
            if r.get("Subnet Name") and r.get("Hosts Needed"):
                mapped_reqs.append({
                    "name": r.get("Subnet Name"),
                    "hosts": r.get("Hosts Needed")
                })
        
        if not mapped_reqs:
            st.warning("Please add at least one requirement.")
            return
            
        with st.spinner("Crunching numbers (sorting, powering, allocating)..."):
            df_result, error = calculate_vlsm(root_cidr, mapped_reqs)
            
        if error:
            st.error(error)
        else:
            # Display Results
            st.success("Allocation Successful!")
            
            # 1. Summary Metrics (Free vs Used)
            stats = get_free_space_summary(root_cidr, df_result)
            m1, m2, m3 = st.columns(3)
            m1.metric("Total IPs", stats.get('Total IPs', 0))
            m2.metric("Allocated IPs", stats.get('Used IPs', 0))
            m3.metric("Free IPs", stats.get('Free IPs', 0), delta_color="normal")
            
            # 2. Visualization (Stacked Bar for Capacity)
            # Reshape for custom colors: Columns = [Allocated, Free]
            chart_data = pd.DataFrame([
                [stats.get('Used IPs', 0), stats.get('Free IPs', 0)]
            ], columns=["Allocated", "Free"])
            
            st.bar_chart(chart_data, color=["#FF4B4B", "#00CC96"]) # Red=Allocated, Green=Free
            
            # 3. Detailed Table
            st.subheader("Allocation Table")
            st.dataframe(
                df_result,
                use_container_width=True,
                column_config={
                    "Utilization %": st.column_config.ProgressColumn(
                        "Utilization %", format="%.1f%%", min_value=0, max_value=100
                    ),
                    "CIDR": st.column_config.TextColumn("CIDR", help="Assigned Subnet Mask"),
                }
            )
            
def render_azure_cost():
    """Renders Azure Egress Cost Calculator."""
    with st.sidebar:
        if st.button("← Back to Home", key="btn_back_azure_cost"):
            st.session_state['current_view'] = 'home'
            st.rerun()
    
    st.title("💸 Azure Data Egress Calculator")
    st.markdown("Estimate bandwidth costs based on standard Azure Internet Egress rates.")
    
    c1, c2 = st.columns(2)
    amount = c1.number_input("Amount", min_value=0.0, value=1.0, step=0.1)
    unit = c2.selectbox("Unit", ["GB", "TB"])
    
    if st.button("Calculate Cost", type="primary"):
        input_gb = amount if unit == "GB" else amount * 1024
        result = calculate_azure_egress(input_gb)
        
        st.divider()
        st.metric("Total Estimated Cost", f"${result['total_cost']}")
        
        st.subheader("Cost Breakdown")
        st.dataframe(pd.DataFrame(result['breakdown']), use_container_width=True)

def render_optical_converter():
    """Renders Optical Power Converter."""
    with st.sidebar:
        if st.button("← Back to Home", key="btn_back_optical"):
            st.session_state['current_view'] = 'home'
            st.rerun()
            
    st.title("🔦 Optical Power Converter")
    st.markdown("Convert between dBm and mW for fiber optic signals.")
    
    c1, c2 = st.columns(2)
    val = c1.number_input("Signal Strength", value=-3.0, step=0.1, format="%.2f")
    unit = c2.selectbox("From Unit", ["dBm", "mW"])
    
    st.divider()
    
    res = convert_optical_power(val, unit)
    if "error" in res:
        st.error(res['error'])
    else:
        st.success(f"Converted: {res['output_val']:.4f} {res['output_unit']}")
        st.metric("Input", res['input'])
        
    st.info("ℹ️ **Reference**: 10G-SR Healthy Range: -3 dBm to -9.9 dBm (RX)")

def render_ip_subtractor():
    """Renders IP Subtractor Tool."""
    with st.sidebar:
        if st.button("← Back to Home", key="btn_back_ip_sub"):
            st.session_state['current_view'] = 'home'
            st.rerun()
            
    st.title("➖ IP Subtractor")
    st.markdown("Exclude a subnet from a Supernet standardly.")
    
    c1, c2 = st.columns(2)
    supernet = c1.text_input("Supernet (e.g., 10.0.0.0/8)", "10.0.0.0/8")
    exclude = c2.text_input("Exclude (e.g., 10.1.0.0/16)", "10.1.0.0/16")
    
    if st.button("Calculate Remaining", type="primary"):
        remaining, err = exclude_subnets(supernet, exclude)
        
        if err:
            st.error(err)
        else:
            st.success(f"Result: {len(remaining)} Subnets Remaining")
            st.code("\n".join(remaining), language="text")

def render_mtu_calculator():
    """Renders Safe MTU & Tunnel Overhead Calculator."""
    with st.sidebar:
        if st.button("← Back to Home", key="btn_back_mtu"):
            st.session_state['current_view'] = 'home'
            st.rerun()
            
    st.title("🚛 MTU & Tunnel Overhead Calculator")
    st.markdown("Calculate safe MTU and MSS to prevent packet fragmentation.")
    
    # Inputs
    c1, c2 = st.columns(2)
    phys_mtu = c1.number_input("Physical Interface MTU", value=1500, step=1)
    
    overheads = {
        "GRE (Generic Routing headers)": 24,
        "GRE + IPsec (Standard VPN)": 56,
        "VXLAN (Data Center Overlay)": 50,
        "WireGuard (Modern VPN)": 60,
        "IPIP (IP in IP Tunnel)": 20
    }
    
    protocol = c2.selectbox("Tunnel Protocol", list(overheads.keys()))
    overhead_val = overheads[protocol]
    
    st.divider()
    
    # Calculation
    res = calculate_mtu_overhead(phys_mtu, overhead_val)
    safe_mtu = res['safe_mtu']
    mss = res['mss']
    
    # Metrics
    m1, m2, m3 = st.columns(3)
    m1.metric("Tunnel Overhead", f"{overhead_val} bytes", delta_color="inverse")
    m2.metric("Safe Tunnel MTU", f"{safe_mtu} bytes", delta="Best Practice", delta_color="normal")
    m3.metric("Recommended MSS", f"{mss} bytes", "Use this value")
    
    # Visual Bar Chart (Packet Anatomy)
    st.subheader("Packet Anatomy")
    
    # Create a DataFrame for the stacked bar
    # We want a single horizontal bar composed of 3 segments
    chart_data = pd.DataFrame({
        "Bytes": [res['breakdown']['Payload (MSS)'], res['breakdown']['TCP/IP Headers'], res['breakdown']['Tunnel Overhead']],
        "Segment": ["Payload (MSS)", "TCP/IP Headers", "Tunnel Overhead"],
        "Type": ["Packet"] * 3 # Dummy column for grouping
    })
    
    st.bar_chart(chart_data, x="Bytes", y="Type", color="Segment", horizontal=True, stack=True)
    
    # Config Snippet
    st.subheader("Configuration Snippet")
    st.markdown("Apply this to your **Tunnel Interface**:")
    config = f"""interface Tunnel100
 ip mtu {safe_mtu}
 ip tcp adjust-mss {mss}"""
    st.code(config, language="network")

def render_bulk_factory():
    """Renders the Bulk Config Factory (CSV + Jinja2)."""
    with st.sidebar:
        if st.button("← Back to Home", key="btn_back_bulk"):
            st.session_state['current_view'] = 'home'
            st.rerun()
            
    st.title("🏭 Bulk Config Factory")
    st.markdown("Generate hundreds of configs using **CSV Data** and **Jinja2 Templates**.")
    
    # 1. Template Input
    st.subheader("1. Template (Jinja2)")
    default_template = """hostname {{ hostname }}
interface GigabitEthernet1/0/1
 description Link to {{ site_name }}
 ip address {{ ip_address }} 255.255.255.0
 no shutdown"""
    template_str = st.text_area("Paste Template Here", value=default_template, height=200, key="bulk_template_input")
    
    # 2. Data Source
    st.subheader("2. Data Source (CSV)")
    
    # Sample CSV
    sample_csv = "hostname,site_name,ip_address\nRouter1,NYC_HQ,192.168.10.1\nRouter2,LA_Branch,192.168.20.1"
    st.download_button("📥 Download Sample CSV", sample_csv, "template.csv", "text/csv")
    
    uploaded_file = st.file_uploader("Upload CSV File (Headers must match template variables)", type=['csv'])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            st.success(f"Loaded {len(df)} rows. Columns: {', '.join(df.columns)}")
            
            # Show data preview
            with st.expander("View Data Preview"):
                st.dataframe(df.head())
            
            # Action Button
            if st.button("🚀 Generate Configs", type="primary"):
                with st.spinner("Rendering templates..."):
                    zip_buffer, preview_list = generate_bulk_configs(template_str, df)
                    
                    st.divider()
                    st.subheader("3. Result Preview")
                    
                    # Preview Tabs
                    if preview_list:
                        tabs = st.tabs([p['filename'] for p in preview_list])
                        for i, tab in enumerate(tabs):
                            with tab:
                                st.code(preview_list[i]['content'])
                    
                    # Download Button
                    st.download_button(
                        label="📦 Download All Configs (.zip)",
                        data=zip_buffer,
                        file_name="bulk_configs.zip",
                        mime="application/zip",
                        type="primary"
                    )
                    
        except Exception as e:
            st.error(f"Error reading CSV: {e}")

def render_subdomain_finder():
    """Renders the Shadow IT Subdomain Finder."""
    with st.sidebar:
        if st.button("← Back to Home", key="btn_back_subdomain"):
            st.session_state['current_view'] = 'home'
            st.rerun()
        st.divider()
        st.info("Queries Certificate Transparency logs to find subdomains.")

    st.title("🕵️‍♂️ Shadow IT Subdomain Finder")
    st.markdown("Find forgotten subdomains and 'Shadow IT' via CT Logs.")

    # Initialize session state for Domain
    if 'crt_domain_q' not in st.session_state:
        st.session_state.crt_domain_q = "openai.com"

    st.caption("Try a Domain:")
    b_cols = st.columns(6)
    if b_cols[0].button("OpenAI", use_container_width=True):
        st.session_state.crt_domain_q = "openai.com"
        st.rerun()
    if b_cols[1].button("Streamlit", use_container_width=True):
        st.session_state.crt_domain_q = "streamlit.io"
        st.rerun()
    if b_cols[2].button("Python", use_container_width=True):
        st.session_state.crt_domain_q = "python.org"
        st.rerun()

    domain = st.text_input("Enter Domain Name", key="crt_domain_q")
    
    if st.button("Find Subdomains", type="primary"):
        if not domain:
             st.warning("Please enter a domain name.")
             return

        with st.spinner(f"Hunting subdomains for {domain}... (crt.sh can be slow, please wait)"):
            results = get_crt_subdomains(domain)
            
        if isinstance(results, dict) and "error" in results:
             st.error(results['error'])
        else:
            count = len(results)
            st.success(f"**Found {count} Unique Subdomains**")
            
            if count > 0:
                st.dataframe(pd.DataFrame(results, columns=["Subdomain"]), use_container_width=True)
                
                # Download
                st.download_button(
                    label="Download List (.txt)",
                    data="\n".join(results),
                    file_name=f"subdomains_{domain}.txt",
                    mime="text/plain"
                )

def inject_custom_css():
    """Injects custom CSS for UI polish."""
    st.markdown("""
        <style>
        /* Hide Streamlit Branding */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        
        /* Card Styling */
        div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlock"] {
            background-color: #f9f9f9;
            border-radius: 10px;
            padding: 10px;
        }
        
        /* Modern Button Hover */
        button[kind="secondary"]:hover {
            border-color: #FF4B4B !important;
            color: #FF4B4B !important;
        }
        
        /* Metrics container */
        [data-testid="stMetricValue"] {
            font-size: 24px;
        }
        </style>
    """, unsafe_allow_html=True)

def draw_tile(col, icon, title, desc, btn_key, view_name):
    """Helper to draw a standardized tool tile."""
    with col:
        with st.container(border=True):
            st.write(f"### {icon} {title}")
            st.caption(desc)
            if st.button(f"Open {title}", key=btn_key, use_container_width=True):
                st.session_state['current_view'] = view_name
                st.rerun()

def render_home():
    """
    Renders the Home page with service tiles for navigation.
    """
    inject_custom_css()
    
    st.title("Network Automation Portal")
    st.info("👋 Welcome to your central hub for network operations and engineering.")
    st.divider()
    
    # Tool Definition (Data-Driven)
    tools = [
        # Row 1: Core Ops
        {"icon": "📡", "title": "Scanner", "desc": "Discovery & Inventory", "view": "scanner"},
        {"icon": "🔐", "title": "SSL Check", "desc": "Cert Expiry Inspector", "view": "ssl_inspector"},
        {"icon": "⚖️", "title": "Config Diff", "desc": "Compare configurations", "view": "config_diff"},
        {"icon": "🌍", "title": "Global DNS", "desc": "Propagation Checker", "view": "dns_propagator"},
        {"icon": "🔢", "title": "Subnet Calc", "desc": "VLSM & Planning", "view": "subnet_calc"},
        
        # Row 2: Analysis & optimization
        {"icon": "⏱️", "title": "Latency", "desc": "HTTP/TCP Analysis", "view": "latency_analyzer"},
        {"icon": "🏭", "title": "Config Gen", "desc": "Multi-Vendor Templates", "view": "config_gen"},
        {"icon": "🛡️", "title": "Net Linter", "desc": "Config Best Practices", "view": "network_linter"},
        {"icon": "🧠", "title": "Optimizer", "desc": "Route Summarization", "view": "route_optimizer"},
        {"icon": "🗺️", "title": "Topology", "desc": "LLDP Visualizer", "view": "topology_mapper"},
        
        # Row 3: Investigation
        {"icon": "🌎", "title": "BGP Look", "desc": "ASN & Peers Graph", "view": "bgp_inspector"},
        {"icon": "🏷️", "title": "MAC Check", "desc": "OUI Vendor Lookup", "view": "mac_inspector"},
        {"icon": "📂", "title": "Log Parser", "desc": "Extract IPs & Errors", "view": "log_extractor"},
        {"icon": "🧮", "title": "TCP Calc", "desc": "BDP & Window Tuning", "view": "tcp_calculator"},
        {"icon": "☁️", "title": "Azure IP", "desc": "Service Tag Ranger", "view": "azure_ranger"},
        
        # Row 4: Security
        {"icon": "🛡️", "title": "Shodan", "desc": "Attack Surface Scan", "view": "shodan_scanner"},
        {"icon": "🕵️‍♂️", "title": "Shadow IT", "desc": "Subdomain Finder", "view": "subdomain_finder"},
        {"icon": "🔐", "title": "ZeroSSL", "desc": "Issue Certificates", "view": "zerossl_manager"},
        {"icon": "🧹", "title": "Sanitizer", "desc": "Redact Passwords/IPs", "view": "config_sanitizer"},
        # Filler for alignment if needed
        
        # Row 5: Utilities
        {"icon": "💸", "title": "Azure Cost", "desc": "Egress Calculator", "view": "azure_cost"},
        {"icon": "🔦", "title": "Optical", "desc": "dBm <-> mW Converter", "view": "optical_converter"},
        {"icon": "➖", "title": "IP Subtract", "desc": "Exclude Subnets", "view": "ip_subtractor"},
        {"icon": "🚛", "title": "MTU Calc", "desc": "Tunnel Overhead", "view": "mtu_calculator"},
        {"icon": "🏭", "title": "Bulk Factory", "desc": "CSV Config Gen", "view": "bulk_factory"},
        {"icon": "📞", "title": "VoIP Calc", "desc": "Bandwidth & Overhead", "view": "voip_calculator"},
        {"icon": "🌐", "title": "IPv6 Master", "desc": "Expand/Compress/Type", "view": "ipv6_master"},
        {"icon": "💸", "title": "Log Cost", "desc": "Data Ingest Estimator", "view": "log_cost_estimator"},
        {"icon": "💾", "title": "Disk IOPS", "desc": "GP3/Azure Limit Calc", "view": "disk_calculator"},
    ]
    
    # Grid Layout Logic
    cols_per_row = 5
    rows = [tools[i:i + cols_per_row] for i in range(0, len(tools), cols_per_row)]
    
    for row_tools in rows:
        cols = st.columns(cols_per_row)
        for idx, tool in enumerate(row_tools):
            draw_tile(
                col=cols[idx],
                icon=tool['icon'],
                title=tool['title'],
                desc=tool['desc'],
                btn_key=f"btn_launch_{tool['view']}",
                view_name=tool['view']
            )
        st.write("") # Spacer between rows
    


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
    elif st.session_state['current_view'] == 'mac_inspector':
        render_mac_inspector()
    elif st.session_state['current_view'] == 'log_extractor':
        render_log_extractor()
    elif st.session_state['current_view'] == 'tcp_calculator':
        render_tcp_calculator()
    elif st.session_state['current_view'] == 'azure_ranger':
        render_azure_ranger()
    elif st.session_state['current_view'] == 'shodan_scanner':
        render_shodan_scanner()
    elif st.session_state['current_view'] == 'subdomain_finder':
        render_subdomain_finder()
    elif st.session_state['current_view'] == 'zerossl_manager':
        render_zerossl_manager()
    elif st.session_state['current_view'] == 'vlsm_architect':
        render_vlsm_architect()
    elif st.session_state['current_view'] == 'azure_cost':
        render_azure_cost()
    elif st.session_state['current_view'] == 'optical_converter':
        render_optical_converter()
    elif st.session_state['current_view'] == 'ip_subtractor':
        render_ip_subtractor()
    elif st.session_state['current_view'] == 'mtu_calculator':
        render_mtu_calculator()
    elif st.session_state['current_view'] == 'bulk_factory':
        render_bulk_factory()
    elif st.session_state['current_view'] == 'config_sanitizer':
        render_config_sanitizer()
    elif st.session_state['current_view'] == 'voip_calculator':
        render_voip_calculator()
    elif st.session_state['current_view'] == 'ipv6_master':
        render_ipv6_master()
    elif st.session_state['current_view'] == 'log_cost_estimator':
        render_log_cost_estimator()
    elif st.session_state['current_view'] == 'disk_calculator':
        render_disk_calculator()
        
    # Global Features
    render_floating_ai_assistant()

if __name__ == "__main__":
    main()
