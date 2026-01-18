import re
import requests
import base64
import time

def extract_urls(text: str):
    return re.compile(r'\b(?:https?://|ftp://|www\.)[\w\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE).findall(text or "")

def is_url_safe_drweb(url: str):
    print(f"[URL] Проверка ссылки: {url}", flush=True)
    try:
        r = requests.post("https://online.drweb.com/result/", data={"url": url},  headers={"User-Agent":"Mozilla/5.0","Referer":"https://online.drweb.com/"}, timeout=15)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    html = r.text.lower()
    if "https://st.drweb.com/pix/online/clean_ru.gif" in html or "https://st.drweb.com/pix/online/clean_en.gif" in html:
        return True
    if "https://st.drweb.com/pix/online/danger_ru.gif" in html or "https://st.drweb.com/pix/online/danger_en.gif" in html or "threat detected" in html:
        return False
    return None

def analyze_urls_in_text(text: str):
    urls = extract_urls(text)
    results = []
    for u in urls:
        dr = is_url_safe_drweb(u)
        malicious = False
        reason = []
        if dr is False:
            malicious = True
            reason.append("drweb")
        results.append({"url": u,"drweb": dr,"malicious": malicious,"reason": reason})
        time.sleep(0.5)
    return results
