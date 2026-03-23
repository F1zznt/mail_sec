import json
import os
import re
import sys
import shutil
from tech import tr
from pathlib import Path
from PySide6.QtWidgets import QApplication,QDialog,QMainWindow,QMessageBox,QHeaderView,QAbstractItemView,QVBoxLayout
from PySide6.QtCore import Qt, QThread, Signal, QFile, QObject, QTimer
from PySide6.QtGui import QStandardItemModel, QStandardItem, QColor, QBrush
from PySide6.QtUiTools import QUiLoader
from email_fetcher import fetch_emails, send_email
from modul_urls import analyze_urls_in_text
from text_analys_modul import is_phishing as analyze_text_model
from attachments_modul import scan_file as analyze_attachment
import mail_db


_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

UI_DIR = _SCRIPT_DIR
DATA_DIR = _SCRIPT_DIR / "attachments"

def _creds_path():
    """Путь к файлу с учётными данными. Пробуем Desktop, Рабочий стол, иначе — папка приложения."""
    home = Path.home()
    for name in ("Desktop", "Рабочий стол"):
        candidate = home / name
        if candidate.is_dir():
            return candidate / "safe_mail_creds.json"
    return _SCRIPT_DIR / "safe_mail_creds.json"

def load_creds():
    """Загружает сохранённые учётные данные."""
    path = _creds_path()
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "provider" not in data or "email" not in data or "password" not in data:
            return None
        data.setdefault("vt_key", data.get("api_key"))
        data.setdefault("api_key", data.get("vt_key"))
        data.setdefault("analyzer", "VirusTotal")
        return data
    except Exception:
        return None


def save_creds(creds):
    """Сохраняет учётные данные"""
    path = _creds_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "provider": creds.get("provider"),
                "email": creds.get("email"),
                "password": creds.get("password"),
                "vt_key": creds.get("api_key") or creds.get("vt_key"),
                "api_key": creds.get("api_key") or creds.get("vt_key"),
                "analyzer": creds.get("analyzer", "VirusTotal"),
            }, f, ensure_ascii=False, indent=2)
        print(f"[GUI] Учётные данные сохранены: {path}", flush=True)
    except Exception as e:
        print(f"[GUI] Ошибка сохранения учётных данных: {e}", flush=True)


def load_ui(ui_path, base_instance):
    """Загружаем ui файлы"""
    path = Path(ui_path)
    f = QFile(str(path))
    loader = QUiLoader()
    root = loader.load(f, None)
    f.close()
    if isinstance(base_instance, QMainWindow) and isinstance(root, QMainWindow):
        base_instance.setWindowTitle(root.windowTitle())
        base_instance.setStyleSheet(root.styleSheet())
        cw = root.centralWidget()
        if cw:
            cw.setParent(None)
            base_instance.setCentralWidget(cw)
            for child in cw.findChildren(QObject):
                name = child.objectName()
                if name:
                    setattr(base_instance, name, child)
        base_instance._ui_root = root
        return root
    layout = QVBoxLayout(base_instance)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(root)
    for child in root.findChildren(QObject):
        name = child.objectName()
        if name:
            setattr(base_instance, name, child)
    if hasattr(root, "size") and callable(getattr(root, "size")):
        sz = root.size()
        if sz.width() > 0 and sz.height() > 0:
            base_instance.setMinimumSize(sz)
    base_instance._ui_root = root
    return root
DATA_DIR.mkdir(exist_ok=True)

def is_commercial(subject: str, text: str):
    try:
        hay = f"{subject} {text}".lower()
        return any(k in hay for k in [ "чек", "яндекс", "yandex", "ya", "ozon", "wildberries", "wb", "avito", "market", "маркетплейс", "скидк", "подар", "акци", "заказ", "маркет", "товар", "недвижимость", "Недвижимость", "Аренд", "аренд", "распродажа", "бонус", "боевик", "триллер", "кино", "урок"])
    except Exception:
        return False


def score_to_color(score):
    """1 — зелёный, 10 — красный"""
    try:
        s = max(1, min(10, int(score)))
    except (TypeError, ValueError):
        s = 1
    t = (s - 1) / 9.0
    r = int(50 + t * 200)
    g = int(200 - t * 200)
    b = int(50 - t * 50)
    return QColor(r, g, b)


def score_from_results(link_verdict,attachment_verdict,text_prob):
    if link_verdict == "PHISHING" or attachment_verdict == "PHISHING":
        return 10, "Фишинг"
    score = 0
    infra_score = 0
    if attachment_verdict == "SUSPICIOUS":
        infra_score += 5
    if link_verdict == "SUSPICIOUS":
        infra_score += 5
    if attachment_verdict == "CLEAN":
        infra_score -= 1
    if link_verdict == "CLEAN":
        infra_score -= 1

    infra_score = max(infra_score, 0)
    text_score = 0
    if text_prob >= 0.999:
        text_score = 4
    elif text_prob >= 0.995:
        text_score = 3
    elif text_prob >= 0.97:
        text_score = 2
    elif text_prob >= 0.85:
        text_score = 1

    synergy = 0
    if infra_score >= 4 and text_score >= 2:
        synergy = 1
    score = infra_score + text_score + synergy
    if infra_score == 0 and text_prob >= 0.995:
        score = max(score, 3)

    score = min(max(score, 1), 10)
    if score >= 9:
        label = "Почти точно атака"
    elif score >= 7:
        label = "Высокий риск"
    elif score >= 5:
        label = "Подозрительно"
    elif score >= 3:
        label = "Низкий риск"
    else:
        label = "Безопасно"
    return score, label


class FetchAndProcessWorker(QThread):
    finished = Signal(list, list)
    progress = Signal(list, list)
    error = Signal(str)

    def __init__(self, provider, email_addr, password, vt_key, analyzer=None, api_key=None, incremental=False, known_ids=None, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.email_addr = email_addr
        self.password = password
        self.vt_key = vt_key
        self.analyzer = analyzer or "VirusTotal"
        self.api_key = api_key if api_key is not None else vt_key
        self.incremental = incremental
        self.known_ids = known_ids or set()

    def run(self):
        mode = "новых " if self.incremental else ""
        print(f"[Воркер] Стадия: загрузка {mode} писем с сервера...", flush=True)
        kwargs = {"save_dir": str(DATA_DIR)}

        if self.incremental:
            kwargs["exclude_ids"] = self.known_ids
            kwargs["limit"] = 100
            messages = fetch_emails(self.provider, self.email_addr, self.password, **kwargs)
            print(f"[Воркер] Ошибка загрузки: {e}", flush=True)
            self.error.emit(str(e))
            return

        total = len(messages)
        if total == 0 and self.incremental:
            print("[Воркер] Новых писем нет.", flush=True)
            self.finished.emit([], [])
            return
        print(f"[Воркер] Загружено писем: {total}. Стадия: анализ по одному.", flush=True)
        inbox = []
        spam = []
        self.progress.emit(inbox, spam)
        for idx, msg in enumerate(messages, 1):
            mid = msg["id"]
            subject = (msg.get("subject", "") or "")[:50]
            print(f"[Воркер] [{idx}/{total}] id={mid} тема={subject!r} ...", flush=True)
            text = msg["text"] or ""
            if is_commercial(subject, text):
                spam.append({"id": mid, "from": msg.get("from"), "subject": msg.get("subject", ""), "text": text, "score": 1, "verdict": "COMMERCIAL", "has_attachments": bool(msg.get("attachments")), "links": [], "attachments": [], "text_prob": 0, "has_malicious_link": False, "has_malicious_attachment": False,})
                print(f"[Воркер]   -> спам (коммерческое)", flush=True)
                self.progress.emit(inbox, spam)
                continue
            links_info = analyze_urls_in_text(text)
            links = [li["url"] for li in links_info]
            has_malicious_link = any(li.get("malicious") for li in links_info)
            link_verdict = "PHISHING" if has_malicious_link else ("CLEAN" if links_info else None)
            text_phish_prob = analyze_text_model(tr(re.sub(r"\b(?:https?://|ftp://|www\.)[\w\-._~:/?#\[\]@!$&\'()*+,;=%]+","[LINK]", text,))).get("phish", 0.0)
            attachments = []
            attachment_verdict = None
            has_malicious_attachment = False
            for at in msg.get("attachments", []):
                att_result = analyze_attachment(at["path"], vt_api_key=self.vt_key, analyzer=self.analyzer, api_key=self.api_key)
                attachments.append({"name": at["name"], "path": at["path"], "result": att_result})
                v = att_result.get("verdict")
                if v == "PHISHING":
                    attachment_verdict = "PHISHING"
                    has_malicious_attachment = True
                    break
                elif v == "SUSPICIOUS" and attachment_verdict != "PHISHING":
                    attachment_verdict = "PHISHING"
                elif v == "CLEAN" and attachment_verdict is None:
                    attachment_verdict = "CLEAN"
            score, verdict = score_from_results(link_verdict=link_verdict, attachment_verdict=attachment_verdict, text_prob=text_phish_prob)
            row = {"id": mid, "from": msg.get("from", "unknown").replace("Попов Олег", "**** ****").replace("Олег", "****").replace("Попов", "*****"), "subject": msg.get("subject", "").replace("Попов Олег", "**** ****").replace("Олег", "****"), "text": text.replace("Попов Олег", "**** ****").replace("Олег", "****"), "links": links, "links_info": links_info, "attachments": attachments, "has_attachments": bool(attachments), "score": score, "verdict": verdict, "text_prob": text_phish_prob, "has_malicious_link": has_malicious_link, "has_malicious_attachment": has_malicious_attachment,}
            inbox.append(row)
            print(f"[Воркер]   -> входящие (вердикт={verdict}, балл={score})", flush=True)
            self.progress.emit(inbox, spam)
        print(f"[Воркер] Анализ завершён. Входящие: {len(inbox)}, Спам: {len(spam)}. Стадия: запись в БД.", flush=True)
        self.finished.emit(inbox, spam)


class InputDataDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        load_ui(UI_DIR / "input_data.ui", self)
        self.setMinimumSize(464, 473)
        self.result = None
        self.pushButton.clicked.connect(self._on_continue)

    def _on_continue(self):
        provider_index = self.provider.currentIndex()
        if provider_index == 0:
            QMessageBox.warning(self, "Ошибка", "Выберите провайдера почты (Google или Yandex).")
            return
        provider = "g" if self.provider.currentText().strip().lower() == "google" else "y"
        email_addr = self.email.text().strip()
        if not email_addr or email_addr == "example@mail.ru":
            QMessageBox.warning(self, "Ошибка", "Введите email.")
            return
        if provider == "g" and not (email_addr.endswith("@gmail.com") or email_addr.endswith("@google.com")):
            QMessageBox.warning(self, "Ошибка", "Для Google укажите адрес @gmail.com или @google.com")
            return
        if provider == "y" and not (email_addr.endswith("@yandex.ru") or email_addr.endswith("@ya.ru")):
            QMessageBox.warning(self, "Ошибка", "Для Yandex укажите адрес @yandex.ru или @ya.ru")
            return
        credentials = self.credentials.text().strip()
        if not credentials or credentials == "IMAP API / App Password":
            QMessageBox.warning(self, "Ошибка", "Введите пароль приложения (Google) или IMAP-ключ/пароль (Yandex).")
            return
        analyze_index = getattr(self, "analyze", None) and self.analyze.currentIndex() or 0
        analyzer = None if analyze_index == 0 else ("VirusTotal" if analyze_index == 1 else "Dr. Web")
        api_key = getattr(self, "apikey", None) and self.apikey.text().strip() or ""
        if api_key == "API Ключ" or not api_key:
            api_key = None
        self.result = {"provider": provider, "email": email_addr, "password": credentials, "vt_key": api_key, "api_key": api_key, "analyzer": analyzer,}
        self.accept()


class MailDialog(QDialog):
  def __init__(self, parent=None):
    super().__init__(parent)
    load_ui(UI_DIR / "mail.ui", self)
    self.setWindowTitle("Письмо")
    self._attachments = []
    btn = getattr(self, "downloadButton", None)
    if btn:
      btn.clicked.connect(self._on_download)

  def set_message(self, m: dict):
    self._attachments = m.get("attachments") or []
    if hasattr(self, "subject"):
      self.subject.setPlainText(m.get("subject", "") or "")
    if hasattr(self, "plainTextEdit_3"):
      self.plainTextEdit_3.setPlainText(m.get("from", "") or "")
    if hasattr(self, "text"):
      self.text.setPlainText(m.get("text", "") or "")
    lines = []
    score = m.get("score")
    verdict = m.get("verdict")
    if score is not None:
      lines.append(f"Итоговый счёт: {score}/10")
    if verdict:
      lines.append(f"Вердикт: {verdict}")
    tp = m.get("text_prob")
    if tp is not None:
      lines.append("[АНАЛИЗ ТЕКСТА]")
      lines.append(f"  Вероятность фишинга: {tp:.5f}")
    links = m.get("links") or []
    if links:
      lines.append("[АНАЛИЗ ССЫЛОК]")
      lines.append(f"  Ссылки: {len(links)}")
      lines.append(f"  Вердикт: {'вредоносные' if m.get('has_malicious_link') else 'проверены, безопасны'}")
      for lnk in links:
        lines.append(f"   - {lnk}")
    else:
      lines.append("[АНАЛИЗ ССЫЛОК] Ссылки не найдены")
    atts = m.get("attachments") or []
    if atts:
      lines.append("[АНАЛИЗ ВЛОЖЕНИЙ]")
      for a in atts:
        res = a.get("result", {})
        lines.append(f"  {a.get('name', '')} -> {res}")
    else:
      lines.append("[АНАЛИЗ ВЛОЖЕНИЙ] Нет вложений")
    if hasattr(self, "result"):
      self.result.setPlainText("\n".join(lines))

  def _on_download(self):
    """Скачать вложения письма"""
    atts = self._attachments or []
    if not atts:
      QMessageBox.information(self, "Вложения", "У этого письма нет вложений.")
      return

    desktop = Path.home() / "Desktop"
    try:
      desktop.mkdir(exist_ok=True)
    except Exception:
      pass

    errors = []
    for a in atts:
      src = a.get("path")
      name = a.get("name") or (os.path.basename(src) if src else "")
      if not src or not os.path.exists(src):
        errors.append(name or (src or "?"))
        continue
      dst = desktop / name
      try:
        shutil.copy2(src, dst)
      except Exception:
        errors.append(name or (src or "?"))
    if errors:
      QMessageBox.warning(self,"Вложения","Некоторые файлы не удалось скопировать:\n" + "\n".join(errors),)
    else:
      QMessageBox.information(self,"Вложения","Все вложения скопированы на рабочий стол.",)


class SendEmailDialog(QDialog):
    def __init__(self, provider, from_email, password, parent=None):
        super().__init__(parent)
        load_ui(UI_DIR / "sendemail.ui", self)
        self.provider = provider
        self.from_email = from_email
        self.password = password
        send_btn = getattr(self, "send", None)
        if send_btn:
            send_btn.clicked.connect(self._on_send)

    def _on_send(self):
        to_w = getattr(self, "to", None)
        to_addr = (to_w.text().strip() if to_w else "").replace("Адресат", "").strip()
        if not to_addr:
            QMessageBox.warning(self, "Ошибка", "Введите адресата.")
            return
        sub_w = getattr(self, "subject", None)
        subject = (sub_w.text().strip() if sub_w else "").replace("Тема", "").strip() or "(без темы)"
        text_w = getattr(self, "text", None)
        body = text_w.toPlainText() if (text_w and hasattr(text_w, "toPlainText")) else (text_w.text() if text_w else "")
        try:
            send_email(self.provider, self.from_email, self.password, to_addr, subject, body or "")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка отправки", str(e))
            return
        mail_db.insert_sent(to_addr, subject, body or "", self.from_email)
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self, credentials, parent=None):
        super().__init__(parent)
        load_ui(UI_DIR / "MainWindow.ui", self)
        self.credentials = credentials
        self.inbox_model = QStandardItemModel(0, 4)
        self.inbox_model.setHorizontalHeaderLabels(["От", "Тема", "Оценка", "Текст"])
        self.all_mail_model = QStandardItemModel(0, 4)
        self.all_mail_model.setHorizontalHeaderLabels(["От", "Тема", "Оценка", "Текст"])
        self.sent_model = QStandardItemModel(0, 3)
        self.sent_model.setHorizontalHeaderLabels(["Кому", "Тема", "Дата"])
        self.inboxTable.setModel(self.inbox_model)
        self.allMailTable.setModel(self.all_mail_model)
        self.sentTable.setModel(self.sent_model)
        self._inbox_rows = []
        self._spam_rows = []
        for tv in (self.inboxTable, self.allMailTable):
            header = tv.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.Fixed)
            header.setSectionResizeMode(1, QHeaderView.Fixed)
            header.setSectionResizeMode(2, QHeaderView.Fixed)
            header.setSectionResizeMode(3, QHeaderView.Stretch)
            header.resizeSection(0, 120)
            header.resizeSection(1, 280)
            header.resizeSection(2, 90)
        for tv in (self.sentTable,):
            header = tv.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.Fixed)
            header.setSectionResizeMode(1, QHeaderView.Fixed)
            header.setSectionResizeMode(2, QHeaderView.Stretch)
            header.resizeSection(0, 120)
            header.resizeSection(1, 280)
            tv.setSelectionBehavior(QAbstractItemView.SelectRows)
            tv.setSelectionMode(QAbstractItemView.SingleSelection)
            tv.setEditTriggers(QAbstractItemView.NoEditTriggers)
            tv.setSelectionBehavior(QAbstractItemView.SelectRows)
            tv.setSelectionMode(QAbstractItemView.SingleSelection)
            tv.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.inboxTable.doubleClicked.connect(lambda idx: self._open_mail_for_row(idx, inbox=True))
        self.allMailTable.doubleClicked.connect(lambda idx: self._open_mail_for_row(idx, inbox=False))
        self.inboxButton.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(0))
        self.allMailButton.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(1))
        self.sentButton.clicked.connect(lambda: self.stackedWidget.setCurrentIndex(2))
        self.sendButton.clicked.connect(self._open_send_dialog)
        refresh_btn = getattr(self, "refreshButton", None)
        if refresh_btn:
            refresh_btn.clicked.connect(self._check_new_emails)
        self.stackedWidget.setCurrentIndex(0)
        self._worker = None
        self._worker_incremental = False
        self._check_timer = None
        self._refresh_tables()
        print("[GUI] Главное окно открыто", flush=True)

    def showEvent(self, event):
        super().showEvent(event)
        if self._worker is None:
            QTimer.singleShot(300, self._start_worker)

    def _start_worker(self):
        if getattr(self, "_worker", None) is not None:
            return
        self._worker_incremental = False
        self._worker = FetchAndProcessWorker(
            self.credentials["provider"],
            self.credentials["email"],
            self.credentials["password"],
            self.credentials.get("vt_key"),
            analyzer=self.credentials.get("analyzer", "VirusTotal"),
            api_key=self.credentials.get("api_key") or self.credentials.get("vt_key"),
        )
        self._worker.finished.connect(self._on_fetch_finished)
        self._worker.progress.connect(self._on_fetch_progress)
        self._worker.error.connect(self._on_fetch_error)
        self._worker.start()
        self.setWindowTitle("Безопасная почта — загрузка и анализ...")
        print("[GUI] Воркер запущен. Таблицы будут заполняться по мере анализа.", flush=True)

    def _on_fetch_error(self, err):
        self.setWindowTitle("Безопасная почта")
        self._worker_incremental = False
        QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить почту:\n{err}")

    def _open_mail_for_row(self, index, inbox: bool):
        model = self.inbox_model if inbox else self.all_mail_model
        rows = self._inbox_rows if inbox else self._spam_rows
        row_idx = index.row()
        first = model.item(row_idx, 0)
        if first is None:
            return
        msg_id = first.data(Qt.UserRole)
        m = next((x for x in rows if x.get("id") == msg_id), None)
        if not m:
            QMessageBox.information(self, "Нет данных", "Подробные данные по этому письму недоступны.")
            return
        dlg = MailDialog(self)
        dlg.set_message(m)
        dlg.exec()

    def _on_fetch_progress(self, inbox, spam):
        if self._worker_incremental:
            self._set_tables_from_lists(list(inbox) + self._inbox_rows, list(spam) + self._spam_rows)
        else:
            self._set_tables_from_lists(inbox, spam)

    def _set_tables_from_lists(self, inbox, spam):
        self._inbox_rows, self._spam_rows = list(inbox), list(spam)
        self.inbox_model.setRowCount(0)
        for r in inbox:
            score = r.get("score", 1)
            verdict = r.get("verdict", "") or f"{score}/10"
            brush = QBrush(score_to_color(score))
            full_from = str(r.get("from", "") or "")
            name = re.split(r"\s*<", full_from)[0].strip()
            text_snip = (r.get("text", "") or "").replace("\n", " ")[:120]
            items = [QStandardItem(name), QStandardItem(str(r.get("subject", ""))), QStandardItem(verdict), QStandardItem(text_snip)]
            items[0].setData(r.get("id"), Qt.UserRole)
            for it in items:
                it.setBackground(brush)
            self.inbox_model.appendRow(items)
        self.all_mail_model.setRowCount(0)
        for r in spam:
            text_snip = (r.get("text", "") or "").replace("\n", " ")[:120]
            score = r.get("score", 1)
            verdict = r.get("verdict", "") or f"{score}/10"
            brush = QBrush(score_to_color(score))
            full_from = str(r.get("from", "") or "")
            name = re.split(r"\s*<", full_from)[0].strip()
            items = [QStandardItem(name), QStandardItem(str(r.get("subject", ""))), QStandardItem(verdict), QStandardItem(text_snip)]
            items[0].setData(r.get("id"), Qt.UserRole)
            for it in items:
                it.setBackground(brush)
            self.all_mail_model.appendRow(items)

    def _on_fetch_finished(self, inbox, spam):
        if self._worker_incremental:
            print("[GUI] Добавление новых писем в БД...", flush=True)
            for row in inbox:
                mail_db.insert_inbox(row)
            for row in spam:
                mail_db.insert_spam(row)
            self._inbox_rows = list(inbox) + self._inbox_rows
            self._spam_rows = list(spam) + self._spam_rows
            self._set_tables_from_lists(self._inbox_rows, self._spam_rows)
            print("[GUI] Добавлено: входящие {}, спам {}.".format(len(inbox), len(spam)), flush=True)
        else:
            print("[GUI] Запись в БД (один раз)...", flush=True)
            mail_db.clear_inbox()
            mail_db.clear_spam()
            for row in inbox:
                mail_db.insert_inbox(row)
            for row in spam:
                mail_db.insert_spam(row)
            self._set_tables_from_lists(inbox, spam)
            self._start_check_timer()
        self._refresh_sent_only()
        self.setWindowTitle("Безопасная почта")
        if not self._worker_incremental:
            print("[GUI] Готово. Входящие: {}, Спам: {}.".format(len(inbox), len(spam)), flush=True)

    def _start_check_timer(self):
        """Запуск таймера проверки новых писем каждые 3 минуты."""
        if self._check_timer is not None:
            return
        self._check_timer = QTimer(self)
        self._check_timer.timeout.connect(self._check_new_emails)
        self._check_timer.start(180000)  # 3 минуты
        print("[GUI] Таймер проверки новых писем: каждые 3 мин.", flush=True)

    def _check_new_emails(self):
        """Проверка и обработка новых писем."""
        if self._worker is not None and self._worker.isRunning():
            print("[GUI] Воркер уже запущен, пропуск проверки.", flush=True)
            return
        known_ids = mail_db.get_known_ids()
        self._worker_incremental = True
        self._worker = FetchAndProcessWorker(
            self.credentials["provider"],
            self.credentials["email"],
            self.credentials["password"],
            self.credentials.get("vt_key"),
            analyzer=self.credentials.get("analyzer", "VirusTotal"),
            api_key=self.credentials.get("api_key") or self.credentials.get("vt_key"),
            incremental=True,
            known_ids=known_ids,
        )
        self._worker.finished.connect(self._on_fetch_finished)
        self._worker.progress.connect(self._on_fetch_progress)
        self._worker.error.connect(self._on_fetch_error)
        self._worker.start()
        self.setWindowTitle("Безопасная почта — проверка новых писем...")
        print("[GUI] Запущена проверка новых писем.", flush=True)

    def _refresh_sent_only(self):
        self.sent_model.setRowCount(0)
        for r in mail_db.get_sent_rows():
            self.sent_model.appendRow([QStandardItem(r.get("to_addr", "")), QStandardItem(r.get("subject", "")), QStandardItem((r.get("date_sent", "") or "")[:19]),])

    def _refresh_tables(self):
        inbox_rows = mail_db.get_inbox_rows()
        self._inbox_rows = [{"id": r.get("id"), "from": r.get("from_addr"), "subject": r.get("subject"), "text": r.get("body", ""), "score": r.get("score", 1), "verdict": r.get("verdict"), "links": [], "attachments": [], "text_prob": 0, "has_malicious_link": False, "has_malicious_attachment": False} for r in inbox_rows]
        self.inbox_model.setRowCount(0)
        for r in inbox_rows:
            text_snip = (r.get("body", "") or "").replace("\n", " ")[:120]
            score = r.get("score", 1)
            verdict = r.get("verdict", "") or f"{score}/10"
            brush = QBrush(score_to_color(score))
            full_from = str(r.get("from_addr", "") or "")
            name = re.split(r"\s*<", full_from)[0].strip()
            items = [QStandardItem(name), QStandardItem(r.get("subject", "")), QStandardItem(verdict), QStandardItem(text_snip)]
            items[0].setData(r.get("id"), Qt.UserRole)
            for it in items:
                it.setBackground(brush)
            self.inbox_model.appendRow(items)
        spam_rows = mail_db.get_spam_rows()
        self._spam_rows = [{"id": r.get("id"), "from": r.get("from_addr"), "subject": r.get("subject"), "text": r.get("body", ""), "score": r.get("score", 1), "verdict": r.get("verdict"), "links": [], "attachments": [], "text_prob": 0, "has_malicious_link": False, "has_malicious_attachment": False} for r in spam_rows]
        self.all_mail_model.setRowCount(0)
        for r in spam_rows:
            text_snip = (r.get("body", "") or "").replace("\n", " ")[:120]
            score = r.get("score", 1)
            verdict = r.get("verdict", "") or f"{score}/10"
            brush = QBrush(score_to_color(score))
            full_from = str(r.get("from_addr", "") or "")
            name = re.split(r"\s*<", full_from)[0].strip()
            items = [QStandardItem(name), QStandardItem(r.get("subject", "")), QStandardItem(verdict), QStandardItem(text_snip)]
            items[0].setData(r.get("id"), Qt.UserRole)
            for it in items:
                it.setBackground(brush)
            self.all_mail_model.appendRow(items)
        self.sent_model.setRowCount(0)
        for r in mail_db.get_sent_rows():
            self.sent_model.appendRow([QStandardItem(r.get("to_addr", "")), QStandardItem(r.get("subject", "")), QStandardItem((r.get("date_sent", "") or "")[:19])])

    def _open_send_dialog(self):
        d = SendEmailDialog(self.credentials["provider"], self.credentials["email"], self.credentials["password"], self)
        if d.exec() == QDialog.Accepted:
            self._refresh_sent_only()


def main():
    mail_db.init_db()
    app = QApplication(sys.argv)
    creds = load_creds()
    if not creds:
        print("Файл учётных данных не найден. Открытие окна ввода...", flush=True)
        dialog = InputDataDialog()
        dialog.setWindowTitle("Ввод данных — Безопасная почта")
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        if dialog.exec() != QDialog.Accepted or not dialog.result:
            return
        creds = dialog.result
        save_creds(creds)
    else:
        print("Найден файл учётных данных. Вход без запроса.", flush=True)
    print("Главное окно с таблицами открывается (таблицы пустые).", flush=True)
    w = MainWindow(creds)
    w.show()
    w.raise_()
    w.activateWindow()
    print("Окно отображено. Ожидайте: сначала загрузка с сервера, затем анализ по одному письму.", flush=True)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
