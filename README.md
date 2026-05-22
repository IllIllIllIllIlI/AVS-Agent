# Autonomous Vulnerability Scanner Agent

> An AI-powered agent that autonomously scans, identifies, and prioritizes vulnerabilities in web applications — combining Nmap, OWASP ZAP, and a fine-tuned LLM to make intelligent decisions about what to scan and how.

> **Origin:** Built during a 24-hour sprint as part of a structured AI/cybersecurity learning project. The sprint produced a working proof-of-concept — this repo is the ongoing effort to turn that into something production-grade.

---

## The Idea

I wanted to build a system that could think like a pentester — not just run tools blindly, but actually decide *which* scans make sense given the target's exposed services. The agent takes a target IP, figures out what's running on it, and autonomously determines the best attack surface to probe.

The original vision was a fully autonomous pipeline requiring zero human input. That vision is mostly intact, with one honest caveat: authenticated scanning against CSRF-protected applications (like DVWA) required more plumbing than expected, which led to some interesting architectural discoveries along the way.

---

## What It Does

```
Target IP → Nmap Scan → LLM Decision → ZAP Scans → Vulnerability Alerts
```

1. **Nmap** enumerates open ports and identifies services
2. A **fine-tuned Llama 3 8B** (`vanessasml/cyber-risk-llama-3-8b`) analyzes the scan results and decides which ZAP scan types are appropriate
3. **OWASP ZAP** executes the chosen scans (spider, ajaxSpider, ascan, pscan)
4. Alerts are collected and returned with full metadata — risk level, confidence, CWE IDs, OWASP references, remediation steps

---

## Stack

| Component | Tool |
|-----------|------|
| Port scanning | `python-nmap` |
| Web scanning | `OWASP ZAP` (Docker, daemon mode) |
| Decision engine | `Llama 3 8B` fine-tuned on cyber risk data |
| Auth handling | `requests` + `BeautifulSoup` |
| Target app | `DVWA` (Docker) |

---

## Architecture

```
app.py                          ← Orchestrator / Agent loop
├── utils/nmap_scanner.py       ← Nmap wrapper + result parser
├── utils/zap_scanner.py        ← ZAP scan execution (spider, ascan, pscan, ajaxSpider)
├── utils/auth.py               ← Login handler (CSRF-aware)
└── model/model_config.py       ← LLM pipeline (HuggingFace transformers)
```

The agent runs as a single Python process. ZAP and DVWA run as separate Docker containers.

---

## Setup

### Prerequisites

- Docker
- Python 3.10+
- ~8GB RAM (LLM + ZAP running simultaneously is heavy)

### 1. Launch DVWA

```bash
docker run --rm -d -p 80:80 vulnerables/web-dvwa
```

Go to `http://localhost/setup.php` and click **Create/Reset Database** before running the agent.

### 2. Launch ZAP

```bash
docker run --rm -d -p 8080:8080 zaproxy/zap-stable zap.sh \
  -daemon -port 8080 -host 0.0.0.0 \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config network.localServers.mainProxy.address=0.0.0.0
```

> **Note:** The `network.localServers.mainProxy.address=0.0.0.0` flag is required. Without it, newer ZAP versions bind to `localhost` inside the container and become unreachable from your host.

### 3. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Run the agent

```bash
python app.py
```

---

## Configuration

In `app.py`, two IP variables control targeting:

```python
target     = "127.0.0.1"   # Used by requests/auth (runs on your machine)
zap_target = "172.17.0.1"  # Used by ZAP (Docker host IP, reachable from ZAP container)
```

If your Docker bridge IP differs from `172.17.0.1`, check with:

```bash
ip route | grep docker
```

---

## The Docker Networking Problem

This took a while to figure out. ZAP runs inside Docker. When it tries to scan `127.0.0.1`, it's scanning *itself* — not DVWA on your host machine. The fix is to use the Docker bridge gateway IP (`172.17.0.1`) as the scan target for ZAP, while keeping `127.0.0.1` for the Python-side auth requests that run directly on the host.

**Before (broken):** ZAP spider finds 3 URLs, all empty alerts.  
**After (fixed):** ZAP reaches DVWA, spider crawls real pages, passive scan returns 20+ alerts.

---

## Known Limitations

**Authenticated scanning is partial.** The agent successfully logs into DVWA and retrieves a valid session cookie. However, ZAP's spider doesn't automatically use `httpsessions` cookies when crawling — it only sees the public-facing pages. Authenticated pages like `/vulnerabilities/sqli/` require either ZAP's context-based auth (which breaks on DVWA's CSRF tokens) or pre-seeding the ZAP site tree by proxying authenticated requests before scanning.

**LLM memory is stateless.** The agent calls the LLM once per run to decide scan types. There's no conversation history or scan-to-scan learning yet.

**RAM usage is high.** Running Llama 3 8B alongside ZAP and an active scan can hit 10-12GB. The LLM decision happens upfront — future improvement would be to unload the model from memory before launching ZAP scans.

---

## What I Learned

Building this forced me to understand the actual internals of ZAP's API rather than just the GUI — a much messier but more honest experience. The `zapv2` Python library has minimal documentation and several deprecated endpoints, which meant reading source code and experimenting directly against the API UI at `http://localhost:8080/UI/`.

The Docker networking issue was the most instructive bug: the same symptom (empty scan results) had three completely different root causes over the course of debugging — wrong endpoint, wrong cookie injection method, and finally wrong IP address. Each fix revealed the next layer.

The project also reinforced that "autonomous" doesn't mean "zero configuration" — it means the *decisions* are automated. The infrastructure setup still requires human judgment about the environment.

---

## Roadmap

- [ ] Parse and score alerts with CVSS mapping
- [ ] Generate HTML/JSON vulnerability reports
- [ ] Add agent memory/state to resume interrupted scans
- [ ] Pre-seed ZAP site tree via authenticated proxy requests (fix deep authenticated scanning)
- [ ] Support multiple target configurations via YAML
- [ ] Unload LLM from memory before scan phase to reduce RAM usage
