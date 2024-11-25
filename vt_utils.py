import requests
import hashlib
import time
import logging
from typing import Optional, Dict

API_KEY = "YOUR_VT_API_KEY"
BASE_URL = "https://www.virustotal.com/api/v3/"
HEADERS = {"x-apikey": API_KEY}

logging.basicConfig(filename="vt_checker.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_event(message: str):
    logging.info(message)

def fetch_data(endpoint: str, identifier: str, retries: int = 3, delay: int = 2) -> Optional[Dict]:
    url = f"{BASE_URL}{endpoint}/{identifier}"
    for attempt in range(retries):
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            return response.json()
        else:
            log_event(f"Attempt {attempt + 1}: Failed to fetch data from {url}. Retrying in {delay} seconds...")
            time.sleep(delay)
    log_event(f"Failed to fetch data from {url} after {retries} retries.")
    return None

def format_detection_ratio(analysis_stats: dict) -> str:
    total_scans = sum(analysis_stats.values())
    detections = analysis_stats.get("malicious", 0)
    return f"{detections}/{total_scans}"

def is_malicious(detection_ratio: str, threshold: int = 2) -> bool:
    detections, _ = map(int, detection_ratio.split("/"))
    return detections > threshold

def check_ip_reputation(ip: str) -> dict:
    data = fetch_data("ip_addresses", ip)
    if not data:
        return {"ip": ip, "reputation": "Error", "country": "Unknown", "detection_ratio": "N/A", "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}/detection"}
    
    attributes = data.get("data", {}).get("attributes", {})
    detection_ratio = format_detection_ratio(attributes.get("last_analysis_stats", {}))
    reputation = "Malicious" if is_malicious(detection_ratio) else "Clean"
    country = attributes.get("country", "Unknown")
    return {"ip": ip, "reputation": reputation, "country": country, "detection_ratio": detection_ratio, "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}/detection"}

def check_url_reputation(url: str) -> dict:
    url_id = hashlib.sha256(url.encode()).hexdigest()
    data = fetch_data("urls", url_id)
    if not data:
        return {"url": url, "reputation": "Error", "detection_ratio": "N/A", "vt_link": f"https://www.virustotal.com/gui/url/{url_id}/detection"}
    
    attributes = data.get("data", {}).get("attributes", {})
    detection_ratio = format_detection_ratio(attributes.get("last_analysis_stats", {}))
    reputation = "Malicious" if is_malicious(detection_ratio) else "Clean"
    return {"url": url, "reputation": reputation, "detection_ratio": detection_ratio, "vt_link": f"https://www.virustotal.com/gui/url/{url_id}/detection"}

def check_hash_reputation(hash_sum: str) -> dict:
    data = fetch_data("files", hash_sum)
    if not data:
        return {"hash": hash_sum, "malicious_detections": "Error", "detection_ratio": "N/A", "vt_link": f"https://www.virustotal.com/gui/file/{hash_sum}/detection"}
    
    attributes = data.get("data", {}).get("attributes", {})
    detection_ratio = format_detection_ratio(attributes.get("last_analysis_stats", {}))
    reputation = "Malicious" if is_malicious(detection_ratio) else "Clean"
    return {"hash": hash_sum, "malicious_detections": attributes.get("last_analysis_stats", {}).get("malicious", 0), "detection_ratio": detection_ratio, "vt_link": f"https://www.virustotal.com/gui/file/{hash_sum}/detection"}
