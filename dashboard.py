import streamlit as st
import pandas as pd
import json
import os
import ipaddress
from network_scanner import scan_network

st.set_page_config(page_title="Network Scanner Dashboard", layout="wide")

st.title("Network Scanner Dashboard")

import datetime

# Metric Tiles Layout
def display_metrics(df):
    total_active = len(df)
    port_80_open = df['port_80'].sum() if 'port_80' in df.columns else 0
    ping_responsive = df['ping'].sum() if 'ping' in df.columns else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Active IPs", total_active)
    col2.metric("Port 80 Open", port_80_open)
    col3.metric("Ping Responsive", ping_responsive)

def load_data():
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

# Sidebar for Scanning
with st.sidebar:
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
st.title("Network Scanner 3.0")

# Create a placeholder for the expander to ensure it's always in the same spot at the top
log_expander = st.expander("Scan Logs (Errors/Warnings)", expanded=False)

# Logic for running scan
if run_scan:
    # Safety Check: Enforce /24 and Private IP unless explicitly ignored (which we won't allow in this version)
    if not is_private_cidr(cidr_input):
        st.error("Safety Violation: Only private IP ranges are allowed (e.g., 192.168.x.x, 10.x.x.x).")
        st.stop()
        
    try:
        network_size = ipaddress.ip_network(cidr_input, strict=False).num_addresses
        if network_size > 256:
             st.error("Safety Violation: Maximum scan size is /24 (256 addresses).")
             st.stop()
    except ValueError:
         st.error("Invalid CIDR format.")
         st.stop()
    
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
        # Calculate rate (approx) - basic implementation
        # For a real smooth rate, we'd track time deltas here.
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

# Scan Summary Block
if 'last_scan_stats' in st.session_state:
    stats = st.session_state['last_scan_stats']
    st.markdown("### Last Scan Summary")
    s1, s2, s3, s4, s5 = st.columns(5)
    s1.metric("Total Scanned", stats.get('total_scanned', 0))
    s2.metric("Duration", f"{stats.get('duration', 0):.2f}s")
    
    rate = stats.get('total_scanned', 0) / (stats.get('duration', 1) or 1)
    s3.metric("Rate", f"{rate:.1f} IP/s")
    s4.metric("Active Found", stats.get('active_count', 0))
    s5.metric("Errors", stats.get('errors', 0))
    st.divider()

if not df.empty:
    display_metrics(df)
    
    st.markdown("### Scan Results")
    
    # Demo Mode Masking
    display_df = df.copy()
    if demo_mode: # Using the demo_mode checkbox from the sidebar
         # Mask IP: 192.168.1.5 -> 192.168.1.***
         display_df['ip'] = display_df['ip'].apply(lambda x: '.'.join(x.split('.')[:3]) + '.***')
         # Mask MAC: 00:11:22:33:44:55 -> 00:11:22:**:**:**
         if 'mac' in display_df.columns:
             display_df['mac'] = display_df['mac'].apply(lambda x: str(x)[:8] + '**:**:**' if x and x != 'Unknown' else x)

    st.dataframe(display_df, use_container_width=True)
    
    # Optional: Filter/Search
    st.markdown("### Search/Filter")
    search_term = st.text_input("Search IP")
    if search_term:
        filtered_df = display_df[display_df['ip'].str.contains(search_term, na=False)]
        st.dataframe(filtered_df, use_container_width=True)

else:
    st.info("No active hosts found.")
    # Show empty dataframe structure
    st.dataframe(pd.DataFrame(columns=["ip", "hostname", "mac", "vendor", "port_80", "ping"]), use_container_width=True)
