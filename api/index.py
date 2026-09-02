from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sqlite3
import json
import random
import datetime
import uuid
import os

app = FastAPI(title="AI-SOC SOAR System", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "/tmp/soc.db" if os.environ.get("VERCEL") else os.path.join(os.path.dirname(__file__), "..", "backend", "soc.db")

_db_initialized = False

def _connect_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _connect_db()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          TEXT PRIMARY KEY,
            timestamp   TEXT NOT NULL,
            source      TEXT NOT NULL,
            severity    TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'New',
            alert_type  TEXT NOT NULL,
            title       TEXT NOT NULL,
            raw_log     TEXT NOT NULL,
            iocs        TEXT NOT NULL DEFAULT '{}',
            risk_score  INTEGER,
            ai_summary  TEXT,
            recommended_playbook TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id        TEXT PRIMARY KEY,
            alert_id  TEXT NOT NULL,
            action    TEXT NOT NULL,
            actor     TEXT NOT NULL,
            details   TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        );

        CREATE TABLE IF NOT EXISTS playbook_steps (
            id          TEXT PRIMARY KEY,
            alert_id    TEXT NOT NULL,
            step_name   TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'Pending',
            result      TEXT,
            executed_at TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id          TEXT PRIMARY KEY,
            alert_id    TEXT NOT NULL,
            channel     TEXT NOT NULL,
            recipient   TEXT NOT NULL,
            message     TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'Sent',
            sent_at     TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        );

        CREATE TABLE IF NOT EXISTS notification_settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL
        );
    """)
    cur.execute("INSERT OR IGNORE INTO notification_settings VALUES ('slack_webhook', '')")
    cur.execute("INSERT OR IGNORE INTO notification_settings VALUES ('email_recipient', 'soc-oncall@enterprise.com')")
    cur.execute("INSERT OR IGNORE INTO notification_settings VALUES ('slack_channel', '#soc-critical-alerts')")
    cur.execute("INSERT OR IGNORE INTO notification_settings VALUES ('notify_critical_only', 'true')")
    conn.commit()
    conn.close()

def ensure_db_initialized():
    global _db_initialized
    if not _db_initialized:
        _db_initialized = True
        try:
            init_db()
            seed_alerts(15)
        except Exception as e:
            print(f"[db_init_error] {e}")

def get_db():
    ensure_db_initialized()
    return _connect_db()

SOURCES = ["CrowdStrike", "SentinelOne", "Okta", "Palo Alto", "Splunk", "Darktrace", "Microsoft Defender"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]

ALERT_TYPES = {
    "Malware Detection": {
        "template": "Malware detected on endpoint {host} — process {proc}",
        "ioc_types": ["hash", "ip", "domain"],
        "playbook": ["Isolate Endpoint", "Block IP/Domain", "Enrich IOC"]
    },
    "Brute Force Login": {
        "template": "Brute force login attempt on account {user} from {ip}",
        "ioc_types": ["ip"],
        "playbook": ["Revoke User Session", "Block IP/Domain", "Enrich IOC"]
    },
    "Lateral Movement": {
        "template": "Suspicious lateral movement from {ip} targeting {host}",
        "ioc_types": ["ip", "hash"],
        "playbook": ["Isolate Endpoint", "Block IP/Domain", "Enrich IOC"]
    },
    "Data Exfiltration": {
        "template": "Potential data exfiltration detected to external domain {domain}",
        "ioc_types": ["domain", "ip"],
        "playbook": ["Block IP/Domain", "Revoke User Session", "Enrich IOC"]
    },
    "Phishing Attempt": {
        "template": "Phishing link clicked by {user}, redirecting to {domain}",
        "ioc_types": ["domain", "ip"],
        "playbook": ["Revoke User Session", "Block IP/Domain", "Enrich IOC"]
    },
    "Privilege Escalation": {
        "template": "Privilege escalation by {user} on host {host}",
        "ioc_types": ["ip", "hash"],
        "playbook": ["Revoke User Session", "Isolate Endpoint", "Enrich IOC"]
    },
    "C2 Communication": {
        "template": "C2 beacon from {host} to remote {ip} detected",
        "ioc_types": ["ip", "domain", "hash"],
        "playbook": ["Isolate Endpoint", "Block IP/Domain", "Enrich IOC"]
    },
    "Ransomware Activity": {
        "template": "Ransomware mass-encryption detected on endpoint {host}",
        "ioc_types": ["hash", "ip"],
        "playbook": ["Isolate Endpoint", "Block IP/Domain", "Enrich IOC"]
    },
}

AI_SUMMARIES = {
    "Malware Detection":    "A known malware signature was detected on the endpoint. The process attempted to establish persistence via registry modifications and initiated outbound connections to suspected C2 infrastructure.",
    "Brute Force Login":    "Automated brute-force activity was detected targeting a user account. Multiple hundreds of failed login attempts were recorded within minutes from a single IP.",
    "Lateral Movement":     "Suspicious internal reconnaissance was detected. An attacker appears to be pivoting from a compromised host using valid credentials.",
    "Data Exfiltration":    "Anomalous outbound data transfer detected to an external domain. Transfer volume significantly exceeds baseline for this endpoint.",
    "Phishing Attempt":     "A user clicked a phishing URL and was redirected to a credential-harvesting lookalike site.",
    "Privilege Escalation": "A user account performed unauthorized privilege escalation matching Windows token manipulation exploits.",
    "C2 Communication":     "Regular beaconing behavior detected from an internal host to an external IP at consistent intervals.",
    "Ransomware Activity":  "Mass file encryption activity detected. Thousands of files were modified with unknown extensions in under two minutes. IMMEDIATE CONTAINMENT REQUIRED.",
}

def rand_ip(): return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
def rand_hash(): return ''.join(random.choices('0123456789abcdef', k=64))
def rand_domain(): return random.choice(["malware-c2", "exploit-kit", "phish-zone", "darkweb-gate"]) + random.choice([".ru", ".cn", ".xyz", ".io"])
def rand_host(): return f"WKSTN-{random.randint(100, 999)}"
def rand_user(): return random.choice(["jsmith", "mwilliams", "abrown", "rjones", "kjohnson", "administrator"])
def rand_proc(): return random.choice(["powershell.exe", "cmd.exe", "svchost.exe", "rundll32.exe"])

def generate_alert():
    atype = random.choice(list(ALERT_TYPES.keys()))
    meta  = ALERT_TYPES[atype]
    host, ip, domain, user, proc = rand_host(), rand_ip(), rand_domain(), rand_user(), rand_proc()
    title    = meta["template"].format(host=host, ip=ip, domain=domain, user=user, proc=proc)
    severity = random.choices(SEVERITIES, weights=[10, 25, 40, 25])[0]
    source   = random.choice(SOURCES)
    now      = datetime.datetime.utcnow()

    iocs = {}
    for ioc_type in meta["ioc_types"]:
        if ioc_type == "ip": iocs["ip_addresses"] = [rand_ip(), rand_ip()]
        elif ioc_type == "hash": iocs["file_hashes"] = [rand_hash()]
        elif ioc_type == "domain": iocs["domains"] = [rand_domain(), rand_domain()]

    raw_log = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now.isoformat() + "Z",
        "source_system": source,
        "alert_type": atype,
        "severity": severity,
        "host": host,
        "user": user,
        "src_ip": ip,
        "process": proc,
        "iocs": iocs
    }
    risk_map = {"Critical": (75, 100), "High": (55, 74), "Medium": (30, 54), "Low": (10, 29)}
    risk_score = random.randint(*risk_map[severity])

    return {
        "id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S") + " UTC",
        "source": source,
        "severity": severity,
        "status": "New",
        "alert_type": atype,
        "title": title,
        "raw_log": json.dumps(raw_log, indent=2),
        "iocs": json.dumps(iocs),
        "risk_score": risk_score,
        "ai_summary": AI_SUMMARIES.get(atype, "Alert requires manual investigation."),
        "recommended_playbook": json.dumps(meta["playbook"]),
        "created_at": now.isoformat(),
    }

def dispatch_notifications(conn, a):
    if a.get("severity") != "Critical": return
    cur = conn.cursor()
    settings = dict(cur.execute("SELECT key, value FROM notification_settings").fetchall())
    slack_channel = settings.get("slack_channel", "#soc-critical-alerts")
    email_recipient = settings.get("email_recipient", "soc-oncall@enterprise.com")
    now_iso = datetime.datetime.utcnow().isoformat() + "Z"

    slack_payload = {
        "text": f"🚨 *CRITICAL SOC ALERT TRIGGERED*",
        "channel": slack_channel,
        "attachments": [{"color": "#ef4444", "fields": [{"title": "Alert ID", "value": a["id"], "short": True}]}]
    }
    email_body = f"CRITICAL INCIDENT ALERT [{a['id']}]\nTitle: {a['title']}"

    cur.execute("INSERT INTO notifications VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), a["id"], "Slack", slack_channel, json.dumps(slack_payload), "Sent (Delivered)", now_iso))
    cur.execute("INSERT INTO notifications VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), a["id"], "Email", email_recipient, email_body, "Sent (Dispatched)", now_iso))
    cur.execute("INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), a["id"], "Instant Alert Sent", "Notification Dispatcher", f"Dispatched to {slack_channel}", now_iso))

def insert_alert(conn, a):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts
          (id,timestamp,source,severity,status,alert_type,title,raw_log,iocs,risk_score,ai_summary,recommended_playbook,created_at)
        VALUES
          (:id,:timestamp,:source,:severity,:status,:alert_type,:title,:raw_log,:iocs,:risk_score,:ai_summary,:recommended_playbook,:created_at)
    """, a)
    for step in json.loads(a["recommended_playbook"]):
        cur.execute("INSERT INTO playbook_steps VALUES (?,?,?,?,?,?)", (str(uuid.uuid4()), a["id"], step, "Pending", None, None))
    conn.commit()
    dispatch_notifications(conn, a)
    conn.commit()

def seed_alerts(count=15):
    conn = _connect_db()
    existing = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if existing == 0:
        for _ in range(count):
            insert_alert(conn, generate_alert())
    conn.close()

class ActionRequest(BaseModel):
    alert_id: str
    action: str
    actor: str = "Analyst"

class WebhookAlert(BaseModel):
    source: str
    severity: str
    alert_type: str
    title: str

class NotificationSettingsRequest(BaseModel):
    slack_channel: Optional[str] = "#soc-critical-alerts"
    slack_webhook: Optional[str] = ""
    email_recipient: Optional[str] = "soc-oncall@enterprise.com"
    notify_critical_only: Optional[str] = "true"

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/")
@app.get("/api")
def api_root():
    return {"message": "AegisGuard AI Backend Running"}

@app.get("/api/alerts")
def get_alerts(severity: str = "All", source: str = "All", status: str = "All", sort_by: str = "created_at", sort_dir: str = "desc"):
    conn = get_db()
    query  = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity and severity != "All": query += " AND severity = ?"; params.append(severity)
    if source and source != "All":     query += " AND source = ?";   params.append(source)
    if status and status != "All":     query += " AND status = ?";   params.append(status)

    allowed = ["created_at", "severity", "source", "status", "risk_score"]
    if sort_by not in allowed: sort_by = "created_at"
    query += f" ORDER BY {sort_by} {'DESC' if sort_dir == 'desc' else 'ASC'}"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    conn  = get_db()
    row   = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert = dict(row)
    alert["playbook_steps"] = [dict(s) for s in conn.execute("SELECT * FROM playbook_steps WHERE alert_id = ? ORDER BY rowid", (alert_id,)).fetchall()]
    alert["audit_logs"] = [dict(a) for a in conn.execute("SELECT * FROM audit_logs WHERE alert_id = ? ORDER BY timestamp DESC", (alert_id,)).fetchall()]
    conn.close()
    return alert

@app.post("/api/alerts/{alert_id}/triage")
def start_triage(alert_id: str):
    conn = get_db()
    conn.execute("UPDATE alerts SET status='Triage in Progress' WHERE id=? AND status='New'", (alert_id,))
    conn.execute("INSERT INTO audit_logs VALUES (?,?,?,?,?,?)", (str(uuid.uuid4()), alert_id, "Triage Started", "AI Engine", "Automated triage initiated.", datetime.datetime.utcnow().isoformat() + "Z"))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/alerts/{alert_id}/action")
def execute_action(alert_id: str, req: ActionRequest):
    conn  = get_db()
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    vt_hits = random.randint(0, 72)
    abuse_conf = random.randint(50, 100)
    ti_match = "Yes" if random.random() > 0.3 else "No"

    results = {
        "Isolate Endpoint":    "Endpoint isolation initiated via EDR API. Host placed in quarantine VLAN.",
        "Revoke User Session": "All active sessions revoked via IdP. MFA reset enforced.",
        "Block IP/Domain":     "Firewall rules updated. IOC added to blocklist.",
        "Enrich IOC":          f"IOC enrichment complete. VirusTotal: {vt_hits}/72 engines flagged. AbuseIPDB confidence: {abuse_conf}%.",
    }
    result_text = results.get(req.action, f"Action '{req.action}' executed successfully.")

    conn.execute("""
        UPDATE playbook_steps SET status='Completed', result=?, executed_at=?
        WHERE alert_id=? AND step_name=? AND status='Pending'
    """, (result_text, datetime.datetime.utcnow().isoformat(), alert_id, req.action))

    conn.execute("INSERT INTO audit_logs VALUES (?,?,?,?,?,?)", (str(uuid.uuid4()), alert_id, req.action, req.actor, result_text, datetime.datetime.utcnow().isoformat() + "Z"))
    conn.execute("UPDATE alerts SET status='Automated Action Taken' WHERE id=?", (alert_id,))

    pending = conn.execute("SELECT COUNT(*) FROM playbook_steps WHERE alert_id=? AND status='Pending'", (alert_id,)).fetchone()[0]
    if pending == 0:
        conn.execute("UPDATE alerts SET status='Resolved' WHERE id=?", (alert_id,))

    conn.commit()
    conn.close()
    return {"success": True, "result": result_text}

@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str):
    conn = get_db()
    conn.execute("UPDATE alerts SET status='Resolved' WHERE id=?", (alert_id,))
    conn.execute("INSERT INTO audit_logs VALUES (?,?,?,?,?,?)", (str(uuid.uuid4()), alert_id, "Resolved", "Analyst", "Alert manually resolved.", datetime.datetime.utcnow().isoformat() + "Z"))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/webhook/alert")
def webhook_alert(alert: WebhookAlert):
    conn = get_db()
    a = generate_alert()
    a.update(source=alert.source, severity=alert.severity, alert_type=alert.alert_type, title=alert.title)
    insert_alert(conn, a)
    conn.close()
    return {"success": True, "alert_id": a["id"]}

@app.get("/api/notifications")
def get_notifications():
    conn = get_db()
    rows = conn.execute("SELECT * FROM notifications ORDER BY sent_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/notifications/test")
def test_notification():
    conn = get_db()
    test_alert = {
        "id": f"ALT-TEST-{uuid.uuid4().hex[:4].upper()}",
        "source": "CrowdStrike",
        "severity": "Critical",
        "alert_type": "Test Critical Alert",
        "title": "Simulated Critical alert dispatched for notification test",
        "risk_score": 98,
        "ai_summary": "Test dispatch verified."
    }
    dispatch_notifications(conn, test_alert)
    conn.close()
    return {"success": True, "message": "Test notification dispatched to Slack and Email"}

@app.get("/api/settings/notifications")
def get_notification_settings():
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM notification_settings").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}

@app.post("/api/settings/notifications")
def update_notification_settings(req: NotificationSettingsRequest):
    conn = get_db()
    cur = conn.cursor()
    if req.slack_channel: cur.execute("INSERT OR REPLACE INTO notification_settings VALUES ('slack_channel', ?)", (req.slack_channel,))
    if req.slack_webhook is not None: cur.execute("INSERT OR REPLACE INTO notification_settings VALUES ('slack_webhook', ?)", (req.slack_webhook,))
    if req.email_recipient: cur.execute("INSERT OR REPLACE INTO notification_settings VALUES ('email_recipient', ?)", (req.email_recipient,))
    if req.notify_critical_only: cur.execute("INSERT OR REPLACE INTO notification_settings VALUES ('notify_critical_only', ?)", (req.notify_critical_only,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Notification settings updated"}

@app.post("/api/login")
def login(req: LoginRequest):
    valid_users = {
        "analyst@aegisguard.io": {"password": "admin", "name": "Alex Morgan", "role": "Lead SOC Analyst"},
        "admin": {"password": "admin", "name": "Alex Morgan", "role": "Lead SOC Analyst"},
        "manaswini": {"password": "admin", "name": "P. Manaswini", "role": "Principal SOC Engineer"},
        "sreeni2357@gmail.com": {"password": "admin", "name": "Sreeni Analyst", "role": "Lead SOC Engineer"}
    }
    u = valid_users.get(req.username.lower())
    if not u or u["password"] != req.password:
        # Accept any valid email or user if password is admin for demo convenience
        if req.password == "admin" and len(req.username) > 3:
            return {
                "success": True,
                "token": f"aegis_token_{uuid.uuid4().hex[:12]}",
                "user": {
                    "name": req.username.split("@")[0].capitalize(),
                    "role": "SOC Security Analyst",
                    "email": req.username
                }
            }
        raise HTTPException(status_code=401, detail="Invalid credentials. Try analyst@aegisguard.io / admin")
    return {
        "success": True,
        "token": f"aegis_token_{uuid.uuid4().hex[:12]}",
        "user": {
            "name": u["name"],
            "role": u["role"],
            "email": req.username
        }
    }

@app.get("/api/stats")
def get_stats():
    conn = get_db()
    def cnt(q, *p): return conn.execute(q, p).fetchone()[0]
    stats = {
        "total":        cnt("SELECT COUNT(*) FROM alerts"),
        "critical":     cnt("SELECT COUNT(*) FROM alerts WHERE severity='Critical'"),
        "high":         cnt("SELECT COUNT(*) FROM alerts WHERE severity='High'"),
        "new":          cnt("SELECT COUNT(*) FROM alerts WHERE status='New'"),
        "resolved":     cnt("SELECT COUNT(*) FROM alerts WHERE status='Resolved'"),
        "actions_taken":cnt("SELECT COUNT(*) FROM audit_logs"),
    }
    conn.close()
    return stats
