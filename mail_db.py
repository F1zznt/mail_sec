import os
import sqlite3
from datetime import datetime

def get_connection():
    conn = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mail_data.db"))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS inbox (
                id TEXT PRIMARY KEY,
                from_addr TEXT,
                subject TEXT,
                body TEXT,
                verdict TEXT,
                score INTEGER,
                has_attachments INTEGER DEFAULT 0,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS spam (
                id TEXT PRIMARY KEY,
                from_addr TEXT,
                subject TEXT,
                body TEXT,
                verdict TEXT,
                score INTEGER,
                has_attachments INTEGER DEFAULT 0,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS sent (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                to_addr TEXT,
                subject TEXT,
                body TEXT,
                from_addr TEXT,
                date_sent TEXT,
                created_at TEXT
            );
        """)
        conn.commit()
    finally:
        conn.close()


def clear_inbox():
    conn = get_connection()
    try:
        conn.execute("DELETE FROM inbox")
        conn.commit()
    finally:
        conn.close()


def clear_spam():
    conn = get_connection()
    try:
        conn.execute("DELETE FROM spam")
        conn.commit()
    finally:
        conn.close()


def insert_inbox(row):
    conn = get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO inbox (id, from_addr, subject, body, verdict, score, has_attachments, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["id"],
                row.get("from", ""),
                row.get("subject", ""),
                row.get("text", "")[:50000],
                row.get("verdict", ""),
                row.get("score", 0),
                1 if row.get("has_attachments") else 0,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def insert_spam(row):
    conn = get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO spam (id, from_addr, subject, body, verdict, score, has_attachments, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["id"],
                row.get("from", ""),
                row.get("subject", ""),
                row.get("text", "")[:50000],
                row.get("verdict", ""),
                row.get("score", 0),
                1 if row.get("has_attachments") else 0,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def insert_sent(to_addr, subject, body, from_addr):
    conn = get_connection()
    try:
        now = datetime.utcnow().isoformat()
        cur = conn.execute(
            """INSERT INTO sent (to_addr, subject, body, from_addr, date_sent, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (to_addr, subject, (body or "")[:50000], from_addr, now, now),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_known_ids():
    """Возвращает id всех писем из inbox и spam для проверки новых."""
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id FROM inbox")
        cur = conn.execute("SELECT id FROM spam")
        inbox_ids = {r[0] for r in cur.fetchall()}
        spam_ids = {r[0] for r in cur.fetchall()}
        return inbox_ids | spam_ids
    finally:
        conn.close()


def get_inbox_rows():
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, from_addr, subject, body, verdict, score FROM inbox ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_spam_rows():
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, from_addr, subject, body, verdict, score FROM spam ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_sent_rows():
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id, to_addr, subject, from_addr, date_sent FROM sent ORDER BY id DESC")
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
