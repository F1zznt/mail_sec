# пофиксить гетатт, добавлять всё в одну папку, не в ядиск и присваивать название по письму. обнулять папки с запуском. Настроить автоматическое получение новых писем
import sys
import os
import re
import shutil
from pathlib import Path
from colorama import Fore, Style, init
import time
from email_fetcher import fetch_emails
from modul_urls import analyze_urls_in_text
from text_analys_modul import is_phishing as analyze_text_model
from attachments_modul import scan_file as analyze_attachment

DATA_DIR = "attachments"
os.makedirs(DATA_DIR, exist_ok=True)
init(autoreset=True)
COMMERCIAL_KEYWORDS = ["чек","яндекс", "yandex", "ya","ozon", "wildberries", "wb","avito", "market", "маркетплейс", "скидк", "подар", "акци" "заказ", "маркет", "товар", "недвижимость", "Недвижимость", "Аренд", "аренд","распродажа", "бонус","боевик", "триллер", "кино"]
def log(m):
    pass
    # print(f"[ДЕБАГ] {m}", flush=True)

def ask_provider():
    while True:
        p = input("Провайдер почты - Google (g) или Yandex (y)? [g/y]: ").strip().lower()
        if p in ("g","y"):
            return p
        print("Введите 'g' или 'y'.")

def ask_email(provider):
    while True:
        email = input("Введите email: ").strip()
        if provider == "g":
            if email.endswith("@gmail.com"):
                return email
            print("Для Google адрес должен оканчиваться на @google.com или @gmail.com")
        else:
            if email.endswith("@yandex.ru") or email.endswith("@ya.ru"):
                return email
            print("Для Yandex адрес должен оканчиваться на @yandex.ru или @ya.ru")

def ask_credentials(provider):
    if provider == "g":
        pwd = input("Введите App Password (Google): ")
    else:
        pwd = input("Введите IMAP API-ключ / пароль (Yandex): ")
    return pwd

def ask_vt_key():
    key = input("Введите API-ключ VirusTotal (или Enter, чтобы пропустить): ").strip()
    return key if key else None

def is_commercial(subject: str, text: str):
    try:
        hay = f"{subject} {text}".lower()
        return any(k in hay for k in COMMERCIAL_KEYWORDS)
    except Exception:
        return False

def score_from_results(link_verdict=None,attachment_verdict=None,text_prob=0.0):
    if link_verdict == "PHISHING":
        return 10, "Фишинг"
    if attachment_verdict == "PHISHING":
        return 10, "Фишинг"
    if attachment_verdict == "SUSPICIOUS":
        return 6, "Подозрительно"
    if link_verdict == "SUSPICIOUS":
        return 6, "Подозрительно"
    if attachment_verdict == "CLEAN" or link_verdict == "CLEAN":
        return 1, "Бузопасно"
    if text_prob >= 0.997:
        return 6, "Возможно Атака"
    elif text_prob >= 0.8:
        return 4, "Немного подозрительно"
    elif text_prob >= 0.5:
        return 2, "Маленький риск"
    return 1, "SAFE"

def color_by_score(score: int):
    if score >= 8:
        return Fore.RED
    if score >= 6:
        return Fore.YELLOW
    if score >= 4:
        return Fore.CYAN
    return Fore.GREEN

def show_summary(msgs):
    print("\nСписок писем:")
    for m in msgs:
        color = color_by_score(m['score'])
        print(color + f"[{m['id']}] {m['subject']} ({m['verdict']}, {m['score']}/10)")
        if m.get('has_attachments'):
            print(Fore.MAGENTA + f"     Вложения: Сохранено в {m['attachment_dir']}")
        print(Style.RESET_ALL)


def show_help():
    print("""
            Доступные команды:
            list / ls                 — список писем (без спама)
            com                       — список коммерческой почты
            show <id> / sh <id>       — краткий просмотр письма
            showfull <id> / sf <id>   — полный текст письма
            links <id>                — ссылки письма
            attachments <id> / att    — список вложений
            getatt <id>               — скопировать вложения на рабочий стол
            help / h                  — показать эту справку
            exit                      — выход
    """)

spam_msgs = []
def run_cli_loop(msgs):
    show_summary(msgs)
    print("Доступные команды: list(ls) - Вся почта, com - комерческая почта/cпам, show(sh) <id> - показать письмо, showfull(sf) <id> - полный анализ, getatt <id> - скачать вожение на рабочий стол, exit")
    while True:
        cmd = input("> ").strip().split()
        if not cmd:
            continue
        if cmd[0] == "list" or cmd[0] ==  "ls":
            show_summary(msgs)
        elif cmd[0] == "show" or cmd[0] ==  "sh" and len(cmd) > 1:
            mid = cmd[1]
            m = next((x for x in msgs if x['id']==mid), None)
            if not m:
                print("Не найдено.")
                continue
            print(f"--- {mid} ---От: {m['from']} Тема: {m['subject']}")
            print("Текст:")
            print(m['text'][:500].replace("\n", " "))
            print("Threat:", m['score'], m['verdict'])
        elif cmd[0] == "showfull" or cmd[0] == "sf" and len(cmd) > 1:
            mid = cmd[1]
            m = next((x for x in msgs if x['id'] == mid), None)
            if not m:
                print("Не найдено.")
                continue

            print(f"\n--- ПОЛНЫЙ АНАЛИЗ ПИСЬМА {mid} ---\n")
            print(color_by_score(m['score']) + f"Итоговый счёт: {m['score']}/10")
            print(color_by_score(m['score']) + f"Вердикт: {m['verdict']}\n")
            tp = m.get('text_prob', 0.0)
            print("[АНАЛИЗ ТЕКСТА]")
            print(f"  Вероятность Фишинга: {tp:.5f}")
            if m['links']:
                link_score = 10 if m['has_malicious_link'] else 5
                print(color_by_score(link_score) + "[АНАЛИЗ ССЫЛОК]")
                print(f"  Ссылки: {len(m['links'])}")
                print(f"  Вердикт: {'вредоносный' if m['has_malicious_link'] else 'подозрительный'}")
                for l in m['links']:
                    print(f"   - {l}")
                print()
            else:
                print(Fore.GREEN + "[АНАЛИЗ ССЫЛОК] Сылки не найдены\n")

            if m['attachments']:
                att_score = 10 if m['has_malicious_attachment'] else 8
                print(color_by_score(att_score) + "[АНАЛИЗ ВЛОЖЕНИЙ]")
                for a in m['attachments']:
                    res = a.get('result', {})
                    print(f"  {a['name']} -> {res}")
                print()
            else:
                print(Fore.GREEN + "[АНАЛИЗ ВЛОЖЕНИЙ] Нет вложений\n")

            print(Style.DIM + "--- Тело письма ---")
            print(m['text'])
        elif cmd[0] == "links" and len(cmd) > 1:
            mid = cmd[1]
            m = next((x for x in msgs if x['id']==mid), None)
            if not m:
                print("Не найдено.")
                continue
            if not m['links']:
                print("Ссылок нет.")
            else:
                for i, link in enumerate(m['links'], 1):
                    print(f"[{i}] {link}")
        elif cmd[0] == "com":
            print("\nКоммерческие сообщения:")
            for m in spam_msgs:
                print(f"[{m['id']}] From: {m['from']} | Subject: {m['subject']}")
        elif cmd[0] == "attachments" and len(cmd) > 1:
            mid = cmd[1]
            m = next((x for x in msgs if x['id']==mid), None)
            if not m:
                print("Не найдено.")
                continue
            if not m['attachments']:
                print("Вложений нет.")
            else:
                for a in m['attachments']:
                    print(f"{a['name']} -> сохранено: {a['path']} (from {mid})")
        elif cmd[0] == "getatt" and len(cmd) > 1:
            mid = cmd[1]
            m = next((x for x in msgs if x['id'] == mid), None)
            if not m or not m.get('has_attachments'):
                print("Вложений нет.")
                continue
            desktop = Path.home() / "Desktop"
            src_dir = Path(m['attachment_dir'])
            for f in src_dir.iterdir():
                shutil.copy(f, desktop / f.name)
            print(f"Вложения письма {mid} скопированы на рабочий стол.")
        elif cmd[0] in ("help", "h"):
            show_help()
        elif cmd[0] == "exit":
            print("Выход.")
            break
        else:
            print("Неизвестная команда.")

def main():
    provider = ask_provider()
    email_addr = ask_email(provider)
    pwd = ask_credentials(provider)
    vt_key = ask_vt_key()
    print("Сбор писем... (может занять некоторое время)")
    try:
        log("Начинаю подключение к IMAP")
        messages = fetch_emails(provider, email_addr, pwd, save_dir=DATA_DIR)
        log(f"Получено писем: {len(messages)}")
    except Exception as e:
        print("Ошибка при получении писем:", e)
        sys.exit(1)

    processed = []
    for msg in messages:
        start = time.time()
        mid = msg['id']
        subject = msg.get('subject', '')
        text = msg['text'] or ""
        if is_commercial(subject, text):
            spam_msgs.append({'id': mid,'from': msg.get('from'),'subject': subject,'text': text,'score': 1,'verdict': "COMMERCIAL"})
            continue
        log(f"Обработка письма #{mid} | Subject: {subject}")
        links_info = analyze_urls_in_text(text)
        links = [li['url'] for li in links_info]
        has_malicious_link = any(li.get("malicious") for li in links_info)
        if links_info:
            if has_malicious_link:
                link_verdict = "PHISHING"
            else:
                link_verdict = "CLEAN"
        else:
            link_verdict = None
        text_no_links = re.sub(r'\b(?:https?://|ftp://|www\.)[\w\-._~:/?#\[\]@!$&\'()*+,;=%]+', '[LINK]', text)
        nt = text_no_links
        text_result = analyze_text_model(nt)
        text_phish_prob = text_result.get('phish', 0.0)
        attachments = []
        attachment_verdict = None
        has_malicious_attachment = False
        for at in msg.get('attachments', []):
            path = at['path']
            name = at['name']
            att_result = analyze_attachment(path, vt_api_key=vt_key)
            attachments.append({'name': name,'path': path,'result': att_result})
            v = att_result.get("verdict")
            if v == "PHISHING":
                attachment_verdict = "PHISHING"
                has_malicious_attachment = True
                break
            elif v == "SUSPICIOUS" and attachment_verdict != "PHISHING":
                attachment_verdict = "SUSPICIOUS"
            elif v == "CLEAN" and attachment_verdict is None:
                attachment_verdict = "CLEAN"
        score, verdict = score_from_results(link_verdict=link_verdict,attachment_verdict=attachment_verdict,text_prob=text_phish_prob)
        has_attachments = bool(attachments)
        attachment_dir = f"{DATA_DIR}/{mid}" if has_attachments else None
        processed.append({'id': mid,'from': msg.get('from', 'unknown'),'subject': msg.get('subject', ''),'text': text,'links': links,'links_info': links_info,'attachments': attachments,'has_attachments': has_attachments,'attachment_dir': attachment_dir,'score': score,'verdict': verdict,'text_flag': text_phish_prob > 0.4,'text_prob': text_phish_prob,'has_malicious_link': has_malicious_link,'has_malicious_attachment': has_malicious_attachment})
        log(f"Письмо #{msg['id']} обработано за {time.time() - start:.2f} сек")
    run_cli_loop(processed)


if __name__ == "__main__":
    main()
