import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import io
import tempfile
import os

def inspect_pcap(file_buffer):
    """
    Parses a PCAP file buffer and returns a DataFrame of packets.
    
    Args:
        file_buffer (bytes/BytesIO): The uploaded PCAP file.
        
    Returns:
        pd.DataFrame: DataFrame containing packet details.
    """
    # Scapy rdpcap expects a filename or file-like object.
    # We'll save to a temp file to be safe and compatible with all scapy versions,
    # or wrap in BytesIO if the version supports it. Tempfile is most robust.
    
    packets = []
    
    try:
        # Streamlit UploadedFile is compatible with some readers, but scapy rdpcap 
        # usually wants a path or real file handle.
        # Let's write to a temp file.
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            tmp.write(file_buffer.getvalue())
            tmp_path = tmp.name

        # Read packets (cap at 1000 to prevent OOM on large files)
        scapy_cap = rdpcap(tmp_path, count=1000)
        
        for i, pkt in enumerate(scapy_cap):
            # Basic Info
            time = float(pkt.time)
            length = len(pkt)
            
            # Layer 3
            src_ip = "N/A"
            dst_ip = "N/A"
            proto_name = "Other"
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
                # Map common protocols
                if proto == 6:
                    proto_name = "TCP"
                elif proto == 17:
                    proto_name = "UDP"
                elif proto == 1:
                    proto_name = "ICMP"
                else:
                    proto_name = str(proto)
            
            # Layer 4 Info
            info = ""
            src_port = ""
            dst_port = ""
            
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                info = f"Flags: {pkt[TCP].flags} Seq: {pkt[TCP].seq}"
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                info = f"Len: {pkt[UDP].len}"
            elif ICMP in pkt:
                info = f"Type: {pkt[ICMP].type} Code: {pkt[ICMP].code}"
                
            packets.append({
                "No.": i + 1,
                "Time": time,
                "Source": src_ip,
                "Destination": dst_ip,
                "Protocol": proto_name,
                "Length": length,
                "SrcPort": src_port,
                "DstPort": dst_port,
                "Info": info
            })
            
        # Clean up
        os.remove(tmp_path)
            
    except Exception as e:
        return pd.DataFrame({"Error": [f"Failed to parse PCAP: {str(e)}"]})
    
    if not packets:
        return pd.DataFrame()
        
    df = pd.DataFrame(packets)
    return df
