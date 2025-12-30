def calculate_voip_bandwidth(num_calls, codec_name, include_l2=True, use_vpn=False, c_rtp=False):
    """
    Calculates VoIP bandwidth requirements per call and total.
    
    Assumption: 20ms packetization (50 pps) for G.711/G.729 as per standard defaults.
    
    Args:
        num_calls (int): Number of concurrent calls.
        codec_name (str): 'G.711 (64k)', 'G.729 (8k)', 'Opus (Wideband)'.
        include_l2 (bool): Include Ethernet Header + Preamble (38 bytes).
        use_vpn (bool): Include IPSec Overhead (~50-60 bytes).
        c_rtp (bool): Use Compressed RTP (cRTP) - reduces IP/UDP/RTP from 40B to 2-4B.
        
    Returns:
        dict: Bandwidth details (kbps/Mbps), PPS, and overhead breakdown.
    """
    # Packetization delay (standard)
    ptime = 20 # ms
    packets_per_second = 1000 / ptime # 50 pps
    
    # 1. Voice Payload
    if 'G.711' in codec_name:
        payload_size = 160 # bytes (64kbps * 20ms / 8)
        codec_bitrate = 64000
    elif 'G.729' in codec_name:
        payload_size = 20 # bytes (8kbps * 20ms / 8)
        codec_bitrate = 8000
    elif 'Opus' in codec_name:
        # Variable, but let's assume a high quality wideband average
        payload_size = 80 # approx 32kbps
        codec_bitrate = 32000
    else:
        # Default fallback G.711
        payload_size = 160
        codec_bitrate = 64000

    # 2. Layer 3/4 Overhead (IP/UDP/RTP)
    if c_rtp:
        l3_overhead = 4 # Compressed RTP (2-4 bytes, typical 4)
    else:
        l3_overhead = 40 # 20 (IP) + 8 (UDP) + 12 (RTP)
        
    # 3. VPN Overhead (IPSec ESP/Tunnel)
    vpn_overhead = 50 if use_vpn else 0 # Conservative average
    
    # 4. Layer 2 Overhead (Ethernet)
    # 14 (Header) + 4 (FCS) + 8 (Preamble) + 12 (IPG) = 38 bytes
    # Some calculators usually just count 14+4=18 (Header+FCS) as "on wire" for Wireshark
    # But for "Bandwidth Planning on Interface", include Preamble/IPG? 
    # Let's stick to standard Ethernet Transport: 18 + 20 (Preamble+IPG) = 38
    l2_overhead = 38 if include_l2 else 0
    
    # Total Packet Size
    total_packet_size = payload_size + l3_overhead + vpn_overhead + l2_overhead
    
    # Bandwidth Calculation per Call
    bandwidth_bps_per_call = total_packet_size * 8 * packets_per_second
    
    # Aggregation
    total_bandwidth_bps = bandwidth_bps_per_call * num_calls
    total_pps = packets_per_second * num_calls
    
    return {
        "calls": num_calls,
        "codec": codec_name,
        "pps": total_pps,
        "packet_size_bytes": total_packet_size,
        "bandwidth_bps_per_call": bandwidth_bps_per_call,
        "total_bandwidth_mbps": total_bandwidth_bps / 1_000_000,
        "total_bandwidth_kbps": total_bandwidth_bps / 1000,
        "breakdown": {
            "Voice Payload": payload_size,
            "L3/L4 Headers": l3_overhead,
            "VPN Overhead": vpn_overhead,
            "L2 Overhead": l2_overhead
        }
    }

def calculate_video_bandwidth(num_calls, quality_profile):
    """
    Estimates Video Conferencing bandwidth.
    
    Profiles (Approximate bi-directional averages):
    - 720p HD: 1.5 Mbps
    - 1080p FHD: 3.0 Mbps
    - 4K UHD: 15.0 Mbps
    """
    profiles = {
        "720p HD": 1.5,
        "1080p FHD": 3.0,
        "4K UHD": 15.0,
        "Standard (480p)": 0.8
    }
    
    per_call_mbps = profiles.get(quality_profile, 1.5)
    total_mbps = per_call_mbps * num_calls
    
    return {
        "calls": num_calls,
        "quality": quality_profile,
        "per_call_mbps": per_call_mbps,
        "total_bandwidth_mbps": total_mbps
    }
