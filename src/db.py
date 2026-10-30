from __future__ import annotations
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH=Path(__file__).resolve().parent.parent/"cyberguardian.db"

def conn():
    c=sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL, src_ip TEXT, dst_ip TEXT,
        attack TEXT NOT NULL, severity TEXT NOT NULL, confidence REAL NOT NULL,
        engine TEXT NOT NULL, action TEXT NOT NULL,
        packet_rate REAL DEFAULT 0, avg_size REAL DEFAULT 0,
        unique_ports INTEGER DEFAULT 0, syn_ratio REAL DEFAULT 0, note TEXT)""")
    c.commit()
    return c

def insert_event(e):
    with conn() as c:
        c.execute("""INSERT INTO events
        (timestamp,src_ip,dst_ip,attack,severity,confidence,engine,action,
         packet_rate,avg_size,unique_ports,syn_ratio,note)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (e.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         e.get("src_ip",""),e.get("dst_ip",""),e["attack"],e["severity"],
         float(e["confidence"]),e["engine"],e["action"],float(e.get("packet_rate",0)),
         float(e.get("avg_size",0)),int(e.get("unique_ports",0)),
         float(e.get("syn_ratio",0)),e.get("note","")))
        c.commit()

def summary():
    with conn() as c:
        total,threats,responses=c.execute("""SELECT COUNT(*),
        COUNT(CASE WHEN attack!='NORMAL' THEN 1 END),
        COUNT(CASE WHEN action!='' THEN 1 END) FROM events""").fetchone()
        rows=c.execute("SELECT attack,COUNT(*) FROM events GROUP BY attack ORDER BY COUNT(*) DESC").fetchall()
    return {"total":int(total or 0),"threats":int(threats or 0),
            "responses":int(responses or 0),"by_attack":dict(rows)}

def timeline():
    with conn() as c:
        return c.execute("""SELECT strftime('%Y-%m-%d %H:00',timestamp) AS hour,
        COUNT(*) FROM events WHERE attack!='NORMAL'
        GROUP BY hour ORDER BY hour""").fetchall()

def timeline_by_attack():
    with conn() as c:
        return c.execute("""SELECT strftime('%Y-%m-%d %H:00',timestamp) AS hour,
        attack, COUNT(*) FROM events WHERE attack!='NORMAL'
        GROUP BY hour, attack ORDER BY hour, attack""").fetchall()

def recent(limit=80):
    with conn() as c:
        return c.execute("""SELECT timestamp,src_ip,dst_ip,attack,severity,confidence,engine,action
        FROM events ORDER BY id DESC LIMIT ?""",(limit,)).fetchall()
