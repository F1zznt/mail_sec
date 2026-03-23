import imaplib
import smtplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import re

# почтовые сервера
IMAP_CONFIG = {"g": ("imap.gmail.com", 993), "y": ("imap.yandex.ru", 993)}
SMTP_CONFIG = {"g": ("smtp.gmail.com", 587), "y": ("smtp.yandex.ru", 587)}

def decode_header_safe(value):
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


def html_to_text(cont):
    if not cont:
        return ""

    cont = re.sub(r'<script.*?>.*?</script>', '', cont, flags=re.DOTALL | re.IGNORECASE)
    cont = re.sub(r'<style.*?>.*?</style>', '', cont, flags=re.DOTALL | re.IGNORECASE)
    cont = re.sub(r'<br\s*/?>', '\n', cont, flags=re.IGNORECASE)
    cont = re.sub(r'<p.*?>', '\n', cont, flags=re.IGNORECASE)
    cont = re.sub(r'</p>', '\n', cont, flags=re.IGNORECASE)
    cont = re.sub(r'<div.*?>', '\n', cont, flags=re.IGNORECASE)
    cont = re.sub(r'</div>', '\n', cont, flags=re.IGNORECASE)
    cont = re.sub(r'<.*?>', '', cont)
    cont = cont.replace('&nbsp;', ' ')
    cont = cont.replace('&lt;', '<')
    cont = cont.replace('&gt;', '>')
    cont = cont.replace('&amp;', '&')
    cont = cont.replace('&quot;', '"')
    cont = re.sub(r'\n\s*\n', '\n\n', cont)
    cont = cont.strip()
    return cont

def extract_text_from_email(msg):
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
        return html_to_text(html_text).strip()
    else:
        return ""

def fetch_emails(provider, email_address, password, mailbox="INBOX", save_dir="attachments", limit=None, exclude_ids=None):
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
    exclude_ids = exclude_ids or set()
    for mail_id in mail_ids:
        status, msg_data = imap.fetch(mail_id, "(RFC822)")
        if status != "OK":
            continue
        msg = email.message_from_bytes(msg_data[0][1])
        msgid = mail_id.decode() if isinstance(mail_id, bytes) else str(mail_id)
        if msgid in exclude_ids:
            continue
        subj = decode_header_safe(msg.get("Subject"))
        from_ = decode_header_safe(msg.get("From"))
        body_text = extract_text_from_email(msg)
        attachments = []
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    filename = decode_header_safe(filename)
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
    imap.close()
    imap.logout()
    return results


def send_email(provider, email_address, password, to_addr, subject, body):
    server, port = SMTP_CONFIG[provider]
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = email_address
    msg["To"] = to_addr
    msg.attach(MIMEText(body or "", "plain", "utf-8"))
    with smtplib.SMTP(server, port) as smtp:
        smtp.starttls()
        smtp.login(email_address, password)
        smtp.sendmail(email_address, [to_addr.strip()], msg.as_string())