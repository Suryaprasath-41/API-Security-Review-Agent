import sqlite3
import json
from datetime import datetime
from app.config import DATABASE_PATH

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 1. Specifications table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS specifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        );
    """)
    
    # 2. Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            spec_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            total_endpoints INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            overall_score REAL DEFAULT 0.0,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (spec_id) REFERENCES specifications(id) ON DELETE CASCADE
        );
    """)
    
    # 3. Findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            owasp_category TEXT,
            owasp_title TEXT,
            exploitability REAL,
            exposure REAL,
            business_impact REAL,
            score REAL,
            explanation TEXT,
            mitigation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)
    
    # 4. Reports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            format TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)
    
    conn.commit()
    conn.close()

def save_specification(filename: str, content_type: str, file_path: str) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    uploaded_at = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO specifications (filename, content_type, file_path, uploaded_at) VALUES (?, ?, ?, ?)",
        (filename, content_type, file_path, uploaded_at)
    )
    spec_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return spec_id

def create_scan(spec_id: int) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    started_at = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO scans (spec_id, status, started_at) VALUES (?, ?, ?)",
        (spec_id, "RUNNING", started_at)
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def update_scan(scan_id: int, status: str, total_endpoints: int, critical_count: int, 
                high_count: int, medium_count: int, low_count: int, overall_score: float):
    conn = get_db_connection()
    cursor = conn.cursor()
    completed_at = datetime.now().isoformat()
    cursor.execute("""
        UPDATE scans 
        SET status = ?, total_endpoints = ?, critical_count = ?, high_count = ?, 
            medium_count = ?, low_count = ?, overall_score = ?, completed_at = ?
        WHERE id = ?
    """, (status, total_endpoints, critical_count, high_count, medium_count, low_count, overall_score, completed_at, scan_id))
    conn.commit()
    conn.close()

def save_finding(scan_id: int, path: str, method: str, rule_id: str, rule_name: str, 
                 severity: str, description: str, owasp_category: str, owasp_title: str,
                 exploitability: float, exposure: float, business_impact: float, score: float, 
                 explanation: str, mitigation: str) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO findings (
            scan_id, path, method, rule_id, rule_name, severity, description, 
            owasp_category, owasp_title, exploitability, exposure, business_impact, 
            score, explanation, mitigation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, path, method, rule_id, rule_name, severity, description,
        owasp_category, owasp_title, exploitability, exposure, business_impact,
        score, explanation, mitigation
    ))
    finding_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return finding_id

def save_report(scan_id: int, file_path: str, format: str) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    created_at = datetime.now().isoformat()
    cursor.execute(
        "INSERT INTO reports (scan_id, file_path, format, created_at) VALUES (?, ?, ?, ?)",
        (scan_id, file_path, format, created_at)
    )
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id

def get_all_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.id, s.spec_id, s.status, s.total_endpoints, s.critical_count, 
               s.high_count, s.medium_count, s.low_count, s.overall_score, 
               s.started_at, s.completed_at, spec.filename 
        FROM scans s
        JOIN specifications spec ON s.spec_id = spec.id
        ORDER BY s.id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan(scan_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.*, spec.filename, spec.file_path 
        FROM scans s
        JOIN specifications spec ON s.spec_id = spec.id
        WHERE s.id = ?
    """, (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_scan_findings(scan_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY score DESC", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan_reports(scan_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE scan_id = ?", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
