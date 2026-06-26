import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            enc_salt      BLOB NOT NULL,
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS entries (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            blob       BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    conn.commit()
    conn.close()


# ---- users ----

def create_user(username: str, password_hash: str, enc_salt: bytes) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, enc_salt) VALUES (?, ?, ?)",
        (username, password_hash, enc_salt),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def get_user_by_username(username: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


# ---- entries ----

def add_entry(user_id: int, blob: bytes) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO entries (user_id, blob) VALUES (?, ?)", (user_id, blob)
    )
    conn.commit()
    entry_id = cur.lastrowid
    conn.close()
    return entry_id


def get_entries(user_id: int):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, blob, created_at, updated_at FROM entries WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    return rows


def get_entry(entry_id: int, user_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM entries WHERE id = ? AND user_id = ?", (entry_id, user_id)
    ).fetchone()
    conn.close()
    return row


def update_entry(entry_id: int, user_id: int, blob: bytes):
    conn = get_db()
    conn.execute(
        "UPDATE entries SET blob = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
        (blob, entry_id, user_id),
    )
    conn.commit()
    conn.close()


def delete_entry(entry_id: int, user_id: int):
    conn = get_db()
    conn.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, user_id))
    conn.commit()
    conn.close()
