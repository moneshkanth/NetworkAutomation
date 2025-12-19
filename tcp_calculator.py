def calculate_tcp_performance(bandwidth, unit, rtt_ms):
    """
    Calculates TCP Bandwidth Delay Product and Theoretical Throughput.
    
    Args:
        bandwidth (float): Link bandwidth value.
        unit (str): "Mbps" or "Gbps".
        rtt_ms (float): Round trip time in milliseconds.
        
    Returns:
        dict: Results including BDP, Max Throughput, and Optimal Window.
    """
    if rtt_ms <= 0:
        return {"error": "RTT must be greater than 0"}
        
    # Convert everything to base units (bits and seconds)
    rtt_sec = rtt_ms / 1000.0
    
    if unit == "Gbps":
        bw_bps = bandwidth * 1_000_000_000
    else: # Mbps
        bw_bps = bandwidth * 1_000_000
        
    # 1. Calculate BDP (Bandwidth Delay Product)
    # This is the amount of data "in flight" to fill the pipe.
    # BDP (Bytes) = (Bandwidth * RTT) / 8
    bdp_bytes = (bw_bps * rtt_sec) / 8
    
    # 2. Calculate Max Theoretical Throughput with Standard Window (64KB)
    # Window Scale Option (RFC 1323) is needed for windows > 64KB (65535 bytes)
    # Throughput <= WindowSize / RTT
    standard_window_bytes = 65535
    max_throughput_standard_bps = (standard_window_bytes * 8) / rtt_sec
    
    # Cap standard throughput at the link bandwidth (can't go faster than physical link)
    actual_throughput_standard_bps = min(max_throughput_standard_bps, bw_bps)
    
    # Convert back to readable units
    bdp_mb = bdp_bytes / (1024 * 1024)
    
    throughput_std_mbps = actual_throughput_standard_bps / 1_000_000
    
    # Efficiency calculation
    link_capacity_mbps = bw_bps / 1_000_000
    efficiency = (throughput_std_mbps / link_capacity_mbps) * 100
    
    return {
        "bdp_bytes": bdp_bytes,
        "bdp_mb": round(bdp_mb, 2),
        "rtt_sec": rtt_sec,
        "standard_window_throughput_mbps": round(throughput_std_mbps, 2),
        "link_capacity_mbps": link_capacity_mbps,
        "efficiency": round(efficiency, 2),
        "optimal_window_size": f"{round(bdp_mb, 2)} MB"
    }
