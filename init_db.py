import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("KF_DB") or os.path.join(HERE, "data", "keys.db")
os.makedirs(os.path.dirname(DB), exist_ok=True)
con = sqlite3.connect(DB)
con.executescript('''
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT UNIQUE,
  val TEXT, prov TEXT, status TEXT DEFAULT "NEW",
  plan TEXT, price TEXT, remaining TEXT,
  found TEXT, repo TEXT, first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS scanned_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_hash TEXT UNIQUE, repo TEXT, path TEXT, scanned TEXT);
CREATE TABLE IF NOT EXISTS git_scanned (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo TEXT UNIQUE, scanned TEXT);
CREATE TABLE IF NOT EXISTS known_repos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo TEXT UNIQUE, source TEXT);
CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status);
CREATE INDEX IF NOT EXISTS idx_keys_val ON keys(val);
CREATE INDEX IF NOT EXISTS idx_scanned_hash ON scanned_files(file_hash);
CREATE INDEX IF NOT EXISTS ix_keys_prov ON keys(prov);
''')
con.commit()
con.close()
print("db initialized:", DB, flush=True)
