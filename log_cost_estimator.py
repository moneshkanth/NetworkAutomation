def calculate_log_cost(daily_gb, retention_days, tier_config=None):
    """
    Calculates estimated monthly cost for log ingestion and storage.

    Args:
        daily_gb (float): Daily ingestion volume in GB.
        retention_days (int): Days to retain data.
        tier_config (dict): Optional custom rates.
            {
                "ingestion_rate": float (per GB),
                "storage_rate": float (per GB/month),
                "included_retention": int (days)
            }

    Returns:
        dict: Detailed breakdown of costs.
    """
    if tier_config is None:
        # Default to a generic SaaS model (e.g., Datadog/Splunk Cloud average)
        # Rates: Ingestion High, Storage included for X days or charged separately
        tier_config = {
            "name": "Standard SaaS (Generic)",
            "ingestion_rate": 2.50, # $2.50 per GB ingested
            "storage_rate": 0.10,   # $0.10 per GB/month for additional retention
            "included_retention": 7 # 7 days often included in base price or standard index
        }
    
    # 1. Ingestion Cost
    # Monthly volume = Daily * 30
    monthly_ingested_gb = daily_gb * 30
    ingestion_cost = monthly_ingested_gb * tier_config["ingestion_rate"]

    # 2. Storage Cost
    # Storage accumulates. But simplified model:
    # Steady State Storage = Daily GB * Retention Days
    # (Assuming we have reached full retention period)
    total_storage_gb = daily_gb * retention_days
    
    # Check if some retention is included/free
    # (e.g. Ingestion covers first 7 days, you only pay for long term)
    billable_storage_gb = max(0, total_storage_gb - (daily_gb * tier_config.get("included_retention", 0)))
    
    storage_cost = billable_storage_gb * tier_config["storage_rate"]
    
    total_monthly_cost = ingestion_cost + storage_cost
    
    return {
        "tier_name": tier_config.get("name", "Custom"),
        "daily_gb": daily_gb,
        "retention_days": retention_days,
        "monthly_ingested_gb": monthly_ingested_gb,
        "total_storage_gb": total_storage_gb,
        "ingestion_cost": round(ingestion_cost, 2),
        "storage_cost": round(storage_cost, 2),
        "total_monthly_cost": round(total_monthly_cost, 2),
        "breakdown": {
            "Ingestion": ingestion_cost,
            "Storage": storage_cost
        }
    }
