# 🛡️ AegisGuard AI — Autonomous SOC & SOAR Platform

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)
![Status](https://img.shields.io/badge/status-active-success)

**AegisGuard AI** is an enterprise-grade, standalone **Autonomous Security Operations Center (SOC) Alert Triage and Automated Incident Response (SOAR)** platform. It features real-time security alert ingestion, AI-driven risk scoring and threat summarization, automated SOAR playbooks, instant Slack & Email notifications, and an immutable audit trail.

---

## ✨ Features

- 🔐 **Authentication & Access Control:** Secure login flow with session persistence and analyst role tracking.
- 📊 **Security Operations Dashboard:** Live operational counters tracking Total Alerts, Critical, High, New, Resolved, and Actions Taken.
- ⚡ **Real-Time Alert Feed & Ingestion:** Webhook endpoints for CrowdStrike, SentinelOne, Okta, Palo Alto, Defender, Splunk, and Darktrace.
- 🧠 **AI Threat Triage Engine:** Numerical risk score assessment (0–100), contextual threat summaries, and automated IOC extraction (IPs, hashes, domains).
- ▶ **SOAR Playbook Execution:** Execute automated responses (Endpoint Isolation, User Session Revocation, IP/Domain Blocking, Threat Enrichment).
- 🔔 **Instant Notification Engine:** Automatic Slack Webhook and Email dispatching for Critical incidents with custom configuration.
- 📋 **Immutable Audit Trail:** Complete audit logging of analyst and AI actions.

---

## 🛠️ Architecture & Tech Stack

- **Backend:** FastAPI (Python 3.10+), SQLite, Pydantic v2, Uvicorn
- **Frontend:** HTML5, Modern CSS3 (Dark Mode SOC UI), Vanilla JavaScript (ES6)

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/AegisGuard-AI.aspx.git
cd AI-SOC
```

### 2. Run with Windows Quick-Launch
```powershell
.\start.bat
```

### 3. Or Run Manually
```powershell
# Create & Activate Virtual Environment
python -m venv venv
.\venv\Scripts\activate

# Install Dependencies
pip install fastapi uvicorn pydantic

# Start Server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)** in your web browser.

---

## 🔑 Demo Login Credentials

| Email / Username | Password | Role |
| :--- | :--- | :--- |
| `analyst@aegisguard.io` | `admin` | Lead SOC Analyst (Alex Morgan) |
| `manaswini` | `admin` | Principal SOC Engineer (P. Manaswini) |

---

## 📜 License

This project is open-source and available under the [MIT License](LICENSE).
