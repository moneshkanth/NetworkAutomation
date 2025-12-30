def get_tool_categories():
    """Returns the categorized list of tools."""
    return {
        "🔍 Reconnaissance & Discovery": [
            {"icon": "📡", "title": "Scanner", "desc": "Discovery & Inventory", "view": "scanner"},
            {"icon": "👁️", "title": "Shodan", "desc": "Internet Exposure", "view": "shodan_scanner"},
            {"icon": "🕵️‍♂️", "title": "Subdomains", "desc": "Shadow IT Finder", "view": "subdomain_finder"},
            {"icon": "🏷️", "title": "MAC Check", "desc": "OUI Vendor Lookup", "view": "mac_inspector"},
            {"icon": "🌎", "title": "BGP Look", "desc": "ASN & Peers Graph", "view": "bgp_inspector"},
            {"icon": "🌍", "title": "Global DNS", "desc": "Propagation Checker", "view": "dns_propagator"},
        ],
        "⚙️ Configuration Operations": [
            {"icon": "⚖️", "title": "Config Diff", "desc": "Compare configurations", "view": "config_diff"},
            {"icon": "🏭", "title": "Config Gen", "desc": "Jinja2 Templates", "view": "config_gen"},
            {"icon": "🏭", "title": "Bulk Factory", "desc": "CSV Config Gen", "view": "bulk_factory"},
            {"icon": "🛡️", "title": "Net Linter", "desc": "Best Practices Check", "view": "network_linter"},
            {"icon": "📋", "title": "Golden Config", "desc": "Compliance Audit", "view": "compliance_engine"},
            {"icon": "🧹", "title": "Sanitizer", "desc": "Redact Secrets", "view": "config_sanitizer"},
        ],
        "📉 Analysis & Visualization": [
            {"icon": "🦈", "title": "PCAP Inspector", "desc": "Wireshark-Lite", "view": "pcap_inspector"},
            {"icon": "🕸️", "title": "Topology", "desc": "LLDP Visualizer", "view": "topology_visualizer"},
            {"icon": "⏱️", "title": "Latency", "desc": "HTTP/TCP Analysis", "view": "latency_analyzer"},
            {"icon": "🧠", "title": "Optimizer", "desc": "Route Summarization", "view": "route_optimizer"},
            {"icon": "📂", "title": "Log Parser", "desc": "Extract IPs & Errors", "view": "log_extractor"},
        ],
        "☁️ Cloud & Planning": [
            {"icon": "☁️", "title": "Azure IP", "desc": "Service Tag Ranger", "view": "azure_ranger"},
            {"icon": "💰", "title": "Azure Cost", "desc": "VM Pricing Calc", "view": "azure_cost"},
            {"icon": "💸", "title": "Log Cost", "desc": "Observability Price", "view": "log_cost_estimator"},
            {"icon": "💾", "title": "Disk IOPS", "desc": "GP3/Azure Thorttle", "view": "disk_calculator"},
        ],
        "🛡️ Security & SSL": [
            {"icon": "🔐", "title": "SSL Check", "desc": "Cert Expiry Check", "view": "ssl_inspector"},
            {"icon": "📜", "title": "ZeroSSL", "desc": "Free Cert Manager", "view": "zerossl_manager"},
        ],
        "🧮 Engineering Calculators": [
            {"icon": "🔢", "title": "Subnet Calc", "desc": "VLSM & Planning", "view": "subnet_calc"},
            {"icon": "✂️", "title": "VLSM Arch", "desc": "Subnet Splitting", "view": "vlsm_architect"},
            {"icon": "➖", "title": "IP Subtract", "desc": "Exclude Subnets", "view": "ip_subtractor"},
            {"icon": "🌐", "title": "IPv6 Master", "desc": "Expand/Compress", "view": "ipv6_master"},
            {"icon": "📞", "title": "VoIP Calc", "desc": "Bandwidth & Overhead", "view": "voip_calculator"},
            {"icon": "🚛", "title": "MTU Calc", "desc": "Tunnel Overhead", "view": "mtu_calculator"},
            {"icon": "​​​​​​​🧮", "title": "TCP Calc", "desc": "Window Tuning", "view": "tcp_calculator"},
            {"icon": "💡", "title": "Optical", "desc": "dBm to mW", "view": "optical_converter"},
        ]
    }
