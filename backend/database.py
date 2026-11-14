import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threats.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flagged_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL,
            scam_category TEXT NOT NULL,
            flag_count INTEGER DEFAULT 0,
            safe_votes INTEGER DEFAULT 0,
            last_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(indicator_type, indicator_value)
        )
    """)
    conn.commit()

    # Seed initial realistic Indian threat intelligence if empty
    cursor.execute("SELECT COUNT(*) as count FROM flagged_threats")
    count = cursor.fetchone()["count"]
    if count == 0:
        seed_data = [
            (
                "url",
                "http://sbi-pan-kyc-update.xyz/verify",
                "Fake Bank / KYC Scam",
                42,
                1,
                "2026-11-13 18:24:10"
            ),
            (
                "upi_id",
                "refund-claim-desk@oksbi",
                "UPI Collect / Refund Fraud",
                37,
                0,
                "2026-11-13 19:40:15"
            ),
            (
                "url",
                "https://parivahan-echallan-pay.apk.top",
                "Electricity / e-Challan Scam",
                29,
                0,
                "2026-11-13 21:05:40"
            ),
            (
                "msg_hash",
                "e3b0c44298fc1c14",
                "Digital Arrest / TRAI Scam",
                25,
                1,
                "2026-11-13 22:15:33"
            ),
            (
                "url",
                "https://bit.ly/power-bill-disconnection-alert",
                "Electricity / e-Challan Scam",
                19,
                0,
                "2026-11-13 23:50:02"
            )
        ]
        cursor.executemany("""
            INSERT OR IGNORE INTO flagged_threats 
            (indicator_type, indicator_value, scam_category, flag_count, safe_votes, last_reported)
            VALUES (?, ?, ?, ?, ?, ?)
        """, seed_data)
        conn.commit()
    conn.close()


def add_or_update_flag(
    indicator_type: str,
    indicator_value: str,
    scam_category: str,
    is_safe: bool = False
) -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    indicator_value = indicator_value.strip()

    # Check if exists
    cursor.execute(
        "SELECT * FROM flagged_threats WHERE indicator_type = ? AND indicator_value = ?",
        (indicator_type, indicator_value)
    )
    row = cursor.fetchone()

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if row:
        if is_safe:
            cursor.execute("""
                UPDATE flagged_threats
                SET safe_votes = safe_votes + 1,
                    last_reported = ?
                WHERE id = ?
            """, (now_str, row["id"]))
        else:
            cursor.execute("""
                UPDATE flagged_threats
                SET flag_count = flag_count + 1,
                    scam_category = ?,
                    last_reported = ?
                WHERE id = ?
            """, (scam_category, now_str, row["id"]))
    else:
        flags = 0 if is_safe else 1
        safes = 1 if is_safe else 0
        cat = "False Positive (Safe)" if is_safe else scam_category
        cursor.execute("""
            INSERT INTO flagged_threats 
            (indicator_type, indicator_value, scam_category, flag_count, safe_votes, last_reported)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (indicator_type, indicator_value, cat, flags, safes, now_str))

    conn.commit()

    cursor.execute(
        "SELECT * FROM flagged_threats WHERE indicator_type = ? AND indicator_value = ?",
        (indicator_type, indicator_value)
    )
    updated_row = cursor.fetchone()
    result = dict(updated_row) if updated_row else {}
    conn.close()
    return result


def get_intel_for_indicators(indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    if not indicators:
        return []
    conn = get_connection()
    cursor = conn.cursor()
    results = []

    for ind in indicators:
        itype = ind.get("type")
        ival = ind.get("value")
        if not itype or not ival:
            continue
        cursor.execute(
            "SELECT * FROM flagged_threats WHERE indicator_type = ? AND indicator_value = ?",
            (itype, ival.strip())
        )
        row = cursor.fetchone()
        if row:
            results.append(dict(row))

    conn.close()
    return results


def get_trending_threats(limit: int = 5) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT indicator_type, indicator_value, scam_category, flag_count, safe_votes, last_reported
        FROM flagged_threats
        WHERE flag_count > 0
        ORDER BY flag_count DESC, last_reported DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
