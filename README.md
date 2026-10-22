# Website Security Checker

A **Streamlit** web app that scans any public website in real time and grades its basic security posture on a scale of **A – F**.

> Built by Jaimine as an educational project. All checks are **passive** — no attacks or intrusive probing are performed.

---

## Features

- **Single-site scan** — enter a URL and get an instant security report
- **Side-by-side comparison** — compare two websites at the same time
- **Shareable links** — results are bookmarkable via `?site=example.com`
- **Dark cybersecurity theme** — clean, readable UI

---

## Security Checks

| # | Check | Points |
|---|-------|--------|
| 1 | HTTPS in use | 20 |
| 2 | HTTP → HTTPS redirect | 10 |
| 3 | Valid SSL certificate + expiry | 20 |
| 4 | `Strict-Transport-Security` (HSTS) | 15 |
| 5 | `Content-Security-Policy` (CSP) | 15 |
| 6 | `X-Frame-Options` | 10 |
| 7 | `X-Content-Type-Options` | 10 |

**Total: 100 points** → graded A (90–100) down to F (< 40).

---

## Safety Measures

Because the app is publicly accessible, several protections are built in:

- **SSRF protection** — private/internal IP ranges are blocked
- **Port allowlist** — only ports 80 and 443 are permitted
- **Redirect re-validation** — every redirect hop is checked before following
- **Timeouts** — every network call has a hard timeout (6 s)
- **Cooldown** — a 3-second cooldown between scans prevents abuse
- **Result caching** — repeated scans for the same site are served from cache for 120 seconds

---

## Getting Started

### Prerequisites

- Python 3.9+
- pip

### Installation

```bash
pip install -r requirements.txt
```

### Run

```bash
streamlit run code.py
```

The app will open at `http://localhost:8501`.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `streamlit` | Web app framework and UI |
| `requests` | HTTP requests to scanned sites |
| `pandas` | Tabular data handling |
| `reportlab` | PDF report export |

---

## Project Structure

```
.
├── code.py           # Main application source
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## Disclaimer

This tool is for **educational and informational purposes only**. A high grade does not guarantee a site is fully secure, and a low grade does not mean a site is compromised. Always consult a qualified security professional for production systems.
