# email_fetcher.py
import imaplib
import email
from email.header import decode_header
import os
import re

IMAP_CONFIG = {"g": ("imap.gmail.com", 993),"y": ("imap.yandex.ru", 993)}

def _decode_header_safe(value):
    if value is None:
        return ""
    parts = decode_header(value)
    decoded_fragments = []
    for fragment, enc in parts:
        if isinstance(fragment, bytes):
            try:
                if enc:
                    decoded_fragments.append(fragment.decode(enc, errors="ignore"))
                else:
                    decoded_fragments.append(fragment.decode("utf-8", errors="ignore"))
            except Exception:
                decoded_fragments.append(fragment.decode("utf-8", errors="ignore"))
        else:
            decoded_fragments.append(fragment)
    return "".join(decoded_fragments)


def _html_to_text(html_content):
    """Конвертирует HTML в простой текст"""
    if not html_content:
        return ""

    html_content = re.sub(r'<script.*?>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r'<style.*?>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r'<br\s*/?>', '\n', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'<p.*?>', '\n', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'</p>', '\n', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'<div.*?>', '\n', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'</div>', '\n', html_content, flags=re.IGNORECASE)
    html_content = re.sub(r'<.*?>', '', html_content)
    html_content = html_content.replace('&nbsp;', ' ')
    html_content = html_content.replace('&lt;', '<')
    html_content = html_content.replace('&gt;', '>')
    html_content = html_content.replace('&amp;', '&')
    html_content = html_content.replace('&quot;', '"')
    html_content = re.sub(r'\n\s*\n', '\n\n', html_content)
    html_content = html_content.strip()
    return html_content

def extract_text_from_email(msg):
    """Рекурсивно извлекает текст из email сообщения"""
    text_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in content_disposition:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        decoded = payload.decode(charset, errors="ignore")
                    except (UnicodeDecodeError, LookupError):
                        decoded = payload.decode("utf-8", errors="ignore")

                    if content_type == "text/plain":
                        text_parts.append(decoded)
                    elif content_type == "text/html":
                        html_parts.append(decoded)
            except Exception:
                continue
    else:
        content_type = msg.get_content_type()
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    decoded = payload.decode(charset, errors="ignore")
                except (UnicodeDecodeError, LookupError):
                    decoded = payload.decode("utf-8", errors="ignore")
                if content_type == "text/plain":
                    text_parts.append(decoded)
                elif content_type == "text/html":
                    html_parts.append(decoded)
        except Exception:
            pass
    if text_parts:
        return "\n".join(text_parts).strip()
    elif html_parts:
        html_text = "\n".join(html_parts)
        return _html_to_text(html_text).strip()
    else:
        return ""

def fetch_emails(provider, email_address, password, mailbox="INBOX", save_dir="attachments", limit=None):
    server, port = IMAP_CONFIG[provider]
    imap = imaplib.IMAP4_SSL(server, port)
    imap.login(email_address, password)
    imap.select(mailbox)
    status, messages = imap.search(None, "ALL")
    if status != "OK":
        raise RuntimeError("Не удалось получить список писем")
    mail_ids = messages[0].split()
    results = []
    os.makedirs(save_dir, exist_ok=True)
    if limit:
        mail_ids = mail_ids[-limit:]
    for mail_id in mail_ids:
        status, msg_data = imap.fetch(mail_id, "(RFC822)")
        if status != "OK":
            continue
        try:
            msg = email.message_from_bytes(msg_data[0][1])
            msgid = mail_id.decode() if isinstance(mail_id, bytes) else str(mail_id)
            subj = _decode_header_safe(msg.get("Subject"))
            from_ = _decode_header_safe(msg.get("From"))
            body_text = extract_text_from_email(msg)
            attachments = []
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition") or "")
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        filename = _decode_header_safe(filename)
                        mail_dir = os.path.join(save_dir, msgid)
                        os.makedirs(mail_dir, exist_ok=True)
                        ext = os.path.splitext(filename)[1] or ".bin"
                        file_index = len(os.listdir(mail_dir)) + 1
                        path = os.path.join(mail_dir, f"{file_index}{ext}")
                        with open(path, "wb") as f:
                            payload = part.get_payload(decode=True)
                            if payload:
                                f.write(payload)
                        attachments.append({"name": filename, "path": path})
            results.append({"id": msgid,"from": from_,"subject": subj,"text": body_text,"attachments": attachments,"raw": msg})
        except Exception as e:
            print(f"Ошибка обработки письма {mail_id}: {e}")
            continue
    imap.close()
    imap.logout()
    return results