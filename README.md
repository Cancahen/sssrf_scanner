# SSRF Scanner Tool

A powerful, multi-threaded **Server-Side Request Forgery (SSRF)** vulnerability scanner. This tool is designed to automate the process of testing parameters for SSRF by injecting various payloads, including local host bypasses, cloud metadata paths, and sensitive file signatures.



## 🚀 Features

* **Multi-threaded Scanning:** High-performance execution using customizable thread counts.
* **Smart Analysis:** Uses a baseline comparison logic (HTTP status, response time, and content similarity) to detect anomalies.
* **Bypass Techniques:** Automatically generates IP bypasses (Hex, Octal, Decimal).
* **Signature Detection:** Scans for AWS/GCP/Azure metadata, sensitive files (`/etc/passwd`), and service banners (Redis, MongoDB).
* **Flexible Targeting:** Supports single IPs, CIDR ranges, domain lists, and local bypasses.
* **OOB/Redirect Support:** Integration for Out-of-Band (OOB) testing.

---

## 🛠 Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/yourusername/ssrf-scanner.git](https://github.com/yourusername/ssrf-scanner.git)
    cd ssrf-scanner
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 📋 Preparation

Before running the script, you must provide the HTTP request you wish to test.

1.  Create a file named `request.txt` in the root directory.
2.  Paste the **raw HTTP request** (copied from Burp Suite or similar tools) into the file.
3.  (Optional) Create `domains.txt` or `ips.txt` if you want to scan specific targets.

---

## 🖥 Usage

Run the main script:
```bash
python ssrf.py
