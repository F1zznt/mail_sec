import os
import time
import requests
from bs4 import BeautifulSoup

VT_API_URL = "https://www.virustotal.com/api/v3"
DRWEB_API_URL = "https://vxcube.drweb.com/api-2.0"

def extract_yadisk_links_from_html(path: str):
    links = []
    with open(path, "r") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "yadi.sk" in href or "disk.yandex" in href:
            links.append(href)
    return links

def download_from_yadisk(public_url: str, save_dir: str):
    """В Яндекс почте большие файлы грузятся на ЯДиск и нужно и парсить"""
    r = requests.get("https://cloud-api.yandex.net/v1/disk/public/resources/download", params={"public_key": public_url}, timeout=10)
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

def virustotal_scan_file(path: str, api_key: str):
    headers = {"x-apikey": api_key}
    file_size = os.path.getsize(path)
    if file_size > 32 * 1024 * 1024:
        r = requests.get(f"{VT_API_BASE}/files/upload_url", headers=headers, timeout=30)
        r.raise_for_status()
        upload_url = r.json().get("data")
    else:
        upload_url = f"{VT_API_BASE}/files"

    with open(path, "rb") as f:
        r = requests.post(upload_url,headers=headers,files={"file": (os.path.basename(path), f, "application/octet-stream")},timeout=300,)
    if r.status_code != 200:
        try:
            err = r.json()
            msg = err.get("error", {}).get("message") or r.text[:500]
        except Exception:
            msg = r.text[:500] if r.text else f"HTTP {r.status_code}"
        raise RuntimeError(f"VirusTotal upload failed: {msg}")
    data = r.json().get("data") or {}
    analysis_id = data.get("id")
    if not analysis_id:
        raise RuntimeError("VirusTotal: no analysis id in response")

    analysis_url = f"{VT_API_BASE}/analyses/{analysis_id}"
    for _ in range(90):
        r = requests.get(analysis_url, headers=headers, timeout=60)
        r.raise_for_status()
        data = r.json().get("data") or {}
        attrs = data.get("attributes") or {}
        status = attrs.get("status", "")
        if status == "completed":
            stats = attrs.get("stats") or {}
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            if malicious >= 1:
                verdict = "PHISHING"
            elif suspicious >= 1:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"
            return {"verdict": verdict, "method": "virustotal", "CleanResult": verdict == "CLEAN", "FoundViruses": [] if verdict == "CLEAN" else ["detected"], "malicious": malicious, "suspicious": suspicious, "undetected": undetected,}
        if status not in ("queued", "in-progress"):
            raise RuntimeError(f"VirusTotal analysis status: {status}")
        time.sleep(20)
    raise RuntimeError("VirusTotal: analysis timeout (waiting for completion)")


def drweb_scan_file(path: str, api_key: str):
    """скан файла Dr.Web"""
    headers = {"Authorization": f"api-key {api_key}"}
    with open(path, "rb") as f:
        r = requests.post(f"{DRWEB_API_BASE}/samples",headers=headers,files={"file": (os.path.basename(path), f)},timeout=120,)

    if r.status_code != 200:
        raise RuntimeError(f"DrWeb: ошибка загрузки файла ({r.text})")

    sample = r.json()
    sample_id = sample.get("id")
    r = requests.post(f"{DRWEB_API_BASE}/analyses",headers=headers,json={"sample_id": sample_id},timeout=30,)
    if r.status_code != 200:
        raise RuntimeError(f"DrWeb: ошибка запуска анализа ({r.text[:300]})")

    analysis = r.json()
    analysis_id = analysis.get("id")
    for _ in range(60):
        r = requests.get(f"{DRWEB_API_BASE}/analyses/{analysis_id}",headers=headers,timeout=30,)
        r.raise_for_status()
        data = r.json()
        tasks = data.get("tasks", [])

        if not tasks:
            time.sleep(10)
            continue

        task = tasks[0]
        status = task.get("status")
        if status in ("successful", "completed"):
            maliciousness = int(task.get("maliciousness", 0))
            verdict_raw = task.get("verdict", "clean")
            if maliciousness >= 5 or "malicious" in verdict_raw:
                verdict = "PHISHING"
            elif maliciousness >= 1:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"
            return {"verdict": verdict,"method": "drweb","CleanResult": verdict == "CLEAN","FoundViruses": [] if verdict == "CLEAN" else ["обнаружено"],"malicious": maliciousness,"suspicious": 0,"undetected": 0,}
        if status in ("queued", "in queue", "running"):
            time.sleep(15)
            continue
        raise RuntimeError(f"DrWeb: неизвестный статус: {status}")
    raise RuntimeError("DrWeb: превышено время ожидания")


def scan_file(path: str, vt_api_key: str = None, analyzer: str = None, api_key: str = None):
    """Сканирует файл. analyzer: 'VirusTotal'|'Dr. Web'|None. api_key или vt_api_key — ключ выбранного анализатора."""
    if not os.path.exists(path):
        return {"verdict": "UNKNOWN", "error": "file not found"}

    ext = os.path.splitext(path)[1].lower()
    if ext in {".html", ".htm"}:
        yadisk_links = extract_yadisk_links_from_html(path)
        if yadisk_links:
            downloaded_files = []
            for link in yadisk_links:
                real_file = download_from_yadisk(link, save_dir=os.path.dirname(path))
                if real_file:
                    downloaded_files.append(real_file)
            if downloaded_files:
                path = downloaded_files[0]
            else:
                return {"verdict": "UNKNOWN", "method": "yadisk", "error": "Не удалось скачать файл с Yandex Disk"}
    key = api_key or vt_api_key
    analyzer_norm = (analyzer or "").strip().lower()

    if key and analyzer_norm in ("dr. web", "drweb"):
        return drweb_scan_file(path, key)
    if key and analyzer_norm in ("virustotal", "vt"):
        return virustotal_scan_file(path, key)