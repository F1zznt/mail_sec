import os
import json
import vt
import requests
from bs4 import BeautifulSoup
import urllib.parse
import time

SUSPICIOUS_EXTS = {
    ".exe", ".scr", ".js", ".vbs", ".cmd", ".bat", ".ps1", ".hta"
}
def extract_yadisk_links_from_html(path: str):
    links = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            soup = BeautifulSoup(f.read(), "html.parser")

        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "yadi.sk" in href or "disk.yandex" in href:
                links.append(href)
    except Exception as e:
        print(e)
    return links

def download_from_yadisk(public_url: str, save_dir: str):
    try:
        api = "https://cloud-api.yandex.net/v1/disk/public/resources/download"
        params = {"public_key": public_url}
        r = requests.get(api, params=params, timeout=10)
        r.raise_for_status()
        download_url = r.json().get("href")
        if not download_url:
            return None

        file_resp = requests.get(download_url, stream=True, timeout=30)
        file_resp.raise_for_status()
        os.makedirs(save_dir, exist_ok=True)
        filename = f"{len(os.listdir(save_dir)) + 1}.bin"
        path = os.path.join(save_dir, filename)
        with open(path, "wb") as f:
            for chunk in file_resp.iter_content(8192):
                f.write(chunk)
        return path
    except Exception:
        return None

def scan_file(path: str, vt_api_key: str = None):
    if not os.path.exists(path):
        return {
            "verdict": "UNKNOWN",
            "error": "file not found"
        }

    ext = os.path.splitext(path)[1].lower()
    if ext in {".html", ".htm"}:
        yadisk_links = extract_yadisk_links_from_html(path)
        if yadisk_links:
            downloaded_files = []
            for link in yadisk_links:
                real_file = download_from_yadisk(link, save_dir=os.path.dirname(path))
                if real_file:
                    downloaded_files.append(real_file)
            if yadisk_links:
                print(yadisk_links)
                downloaded_files = []
                for link in yadisk_links:
                    real_file = download_from_yadisk(link, save_dir=os.path.dirname(path))
                    print(real_file)
                    if real_file:
                        downloaded_files.append(real_file)

                if downloaded_files:
                    path = downloaded_files[0]
                else:
                    return {"verdict": "UNKNOWN","method": "yadisk","error": "Не удалось скачать файл с Yandex Disk"}
    if ext in SUSPICIOUS_EXTS:
        heuristic_verdict = "SUSPICIOUS"
    else:
        heuristic_verdict = "UNKNOWN"

    if vt_api_key:
        try:
            client = vt.Client(vt_api_key)
            print(f"пошёл обрабатывать файл {path}")
            with open(path, "rb") as f:
                analysis = client.scan_file(f)

            analysis = client.get_object(f"/analyses/{analysis.id}")
            print(analysis)
            stats = analysis.stats
            print(stats)
            vt_verdict = verdict_from_vt_stats(stats)
            print(vt_verdict)
            client.close()
            return {"verdict": vt_verdict,"stats": stats,"method": "virustotal","malicious": stats.get("malicious", 0),"suspicious": stats.get("suspicious", 0),"undetected": stats.get("undetected", 0)}
        except Exception as e:
            return {"verdict": heuristic_verdict,"method": "heuristic","error": str(e)}
    return {"verdict": heuristic_verdict,"method": "heuristic"}

def verdict_from_vt_stats(stats: dict):
    mal = stats.get("malicious", 0)
    susp = stats.get("suspicious", 0)
    undet = stats.get("undetected", 0)
    if mal >= 3:
        return "PHISHING"
    elif mal >= 1 or susp >= 2:
        return "SUSPICIOUS"
    elif undet >= 30:
        return "CLEAN"
    return "UNKNOWN"