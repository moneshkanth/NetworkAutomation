# Network Scanner Dashboard

A Python-based network scanner with a modern Streamlit interface. Identifies active devices on your local network, resolves hostnames, retrieves MAC addresses, and looks up vendor information. Designed for network administrators and SREs.

## Features

-   **Active Scanning**: Scans CIDR blocks (e.g., `192.168.1.0/24`) for active hosts using ICMP and ARP.
-   **Device Identification**:
    -   Hostnames (via DNS/mDNS).
    -   MAC Addresses (via ARP table).
    -   Vendor/Manufacturer (via MAC OUI lookup).
-   **Live Dashboard**: Real-time progress bar, status logs, and scan metrics.
-   **Run History**: Persistent log of past scans (Timestamp, CIDR, Active Count).
-   **Safety & Privacy**:
    -   Strictly enforces private IP ranges.
    -   "Demo Mode" to mask sensitive IPs/MACs for sharing/screenshots.
    -   Rate limiting to respect API usage policies.

## Prerequisites

-   Python 3.8+
-   Tested on macOS/Linux (Windows usage may require adjustments to `arp` commands).

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/moneshkanth/NetworkAutomation.git
    cd NetworkAutomation
    ```

2.  Create a virtual environment:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Run the dashboard:
    ```bash
    streamlit run dashboard.py
    ```
    *Alternatively, use the helper script:* `./run_dashboard.sh`

2.  Open your browser to `http://localhost:8501`.

3.  Enter a CIDR block (e.g., `192.168.1.0/24`) and click **Run Scan**.

## Project Structure

-   `dashboard.py`: Main Streamlit application and UI logic.
-   `network_scanner.py`: Core scanning logic (threading, ARP, sockets).
-   `scan_results.json`: Stores the most recent aggregated scan results.
-   `scan_history.json`: Persists metadata of past scan executions.

## License

MIT
