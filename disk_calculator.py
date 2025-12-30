def calculate_disk_performance(size_gb, disk_type):
    """
    Calculates Max IOPS and Throughput for Cloud Disks.

    Args:
        size_gb (int): Disk size in GB.
        disk_type (str): 'AWS GP3' or 'Azure Premium SSD'.

    Returns:
        dict: Performance metrics (IOPS, MB/s) and notes.
    """
    result = {
        "size_gb": size_gb,
        "disk_type": disk_type,
        "iops": 0,
        "throughput_mbps": 0,
        "notes": ""
    }

    if disk_type == "AWS GP3":
        # AWS GP3 Logic
        # Baseline: 3,000 IOPS
        # Throughput: 125 MB/s
        # Scaling: Only if provisioned explicitly, but user simplified logic:
        # "If size > 1000GB, add 500 IOPS per TB"
        
        base_iops = 3000
        base_throughput = 125
        
        result["iops"] = base_iops
        result["throughput_mbps"] = base_throughput
        
        if size_gb > 1000:
            extra_tb = (size_gb - 1000) / 1000
            # Scaling logic per simplified request
            result["iops"] += int(extra_tb * 500)
            
        result["notes"] = "Baseline performance. GP3 allows independent provisioning (paid)."

    elif disk_type == "Azure Premium SSD":
        # Azure P-Series Logic (Approximation)
        # P10 (128G) = 500 IOPS, 100 MB/s
        # P15 (256G) = 1100 IOPS, 125 MB/s
        # P20 (512G) = 2300 IOPS, 150 MB/s
        # P30 (1024G) = 5000 IOPS, 200 MB/s
        # P40 (2048G) = 7500 IOPS, 250 MB/s
        # P50 (4096G) = 7500 IOPS, 250 MB/s (Cap increases later)
        
        # Simplified Lookup for "Standard" sizes
        if size_gb <= 128:
            result["iops"] = 500
            result["throughput_mbps"] = 100
            result["notes"] = "Tier P10. Bursting available for small sizes."
        elif size_gb <= 256:
            result["iops"] = 1100
            result["throughput_mbps"] = 125
            result["notes"] = "Tier P15"
        elif size_gb <= 512:
            result["iops"] = 2300
            result["throughput_mbps"] = 150
            result["notes"] = "Tier P20"
        elif size_gb <= 1024:
            result["iops"] = 5000
            result["throughput_mbps"] = 200
            result["notes"] = "Tier P30"
        elif size_gb <= 2048:
            result["iops"] = 7500
            result["throughput_mbps"] = 250
            result["notes"] = "Tier P40"
        elif size_gb <= 4096:
            result["iops"] = 7500
            result["throughput_mbps"] = 250
            result["notes"] = "Tier P50"
        elif size_gb <= 8192:
            result["iops"] = 16000
            result["throughput_mbps"] = 500
            result["notes"] = "Tier P60"
        else:
            result["iops"] = 20000
            result["throughput_mbps"] = 900
            result["notes"] = "Tier P70/P80 (Max)"
            
    return result
