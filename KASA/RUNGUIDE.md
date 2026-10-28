# KASA — Kernel Attack Surface Analyzer
## Complete Run Guide

> **KASA** scans a live Linux system for kernel security misconfigurations, then uses an AI model to explain real attack possibilities and generate prioritized remediation commands.

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Installation](#2-installation)
3. [AI Providers](#3-ai-providers)
4. [Local AI via Ollama (Offline)](#4-local-ai-via-ollama-offline)
5. [Command Reference](#5-command-reference)
6. [Web Dashboard](#6-web-dashboard)
7. [Full Demo Sequence](#7-full-demo-sequence)
8. [Output Examples](#8-output-examples)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Quick Start

```bash
# Activate the virtual environment
cd ~/KASA
source .venv/bin/activate

# Run full AI security analysis (uses built-in API key automatically)
kasa ai

# Open interactive web dashboard
kasa --dashboard
```

> [!NOTE]
> A built-in OpenRouter API key is pre-configured. No setup required for cloud analysis.

---

## 2. Installation

```bash
# Clone the project
git clone https://github.com/DHARSHAN-14/KASA.git
cd KASA

# Create virtual environment & install
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[ai,dev]"

# Verify installation
kasa version
kasa providers
```

**Requirements**
- Python 3.10+
- Linux (reads `/proc`, `/sys`, kernel modules)
- Ollama (optional, for local offline AI)

---

## 3. AI Providers

KASA supports **6 AI providers**. The built-in OpenRouter key is configured by default.

```bash
# Check which providers are active
kasa providers
```

```
Provider       Default Model              Status
────────────────────────────────────────────────────────────
deepseek       deepseek-chat              ✗ no key
openrouter     qwen/qwen3-235b-a22b       ✓ READY (built-in)
together       Qwen/Qwen3-235B-A22B       ✗ no key
fireworks      qwen3-235b-a22b            ✗ no key
gemini         gemini-2.0-flash           ✗ no key
ollama         qwen2.5:3b                 ✓ READY (local)
```

### Setting Your Own API Key (Optional)

```bash
# Universal key — provider auto-detected from key format:
export KASA_API_KEY="your-key-here"

# Or provider-specific:
export OPENROUTER_API_KEY="sk-or-..."      # → qwen3-235b / deepseek / llama
export DEEPSEEK_API_KEY="sk-..."           # → deepseek-chat / deepseek-r1
export GEMINI_API_KEY="AIza..."            # → gemini-2.0-flash
export TOGETHER_API_KEY="..."              # → qwen3-235b / llama
export FIREWORKS_API_KEY="fw_..."          # → qwen3-235b / deepseek
```

Key format auto-detection:

| Key prefix | Provider detected |
|---|---|
| `sk-or-...` | OpenRouter |
| `sk-...` | DeepSeek |
| `AIza...` | Google Gemini |
| `fw_...` | Fireworks AI |
| 32+ chars | Together AI |

---

## 4. Local AI via Ollama (Offline)

Run completely **offline** — no internet, no API key needed.

### Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Download Models

```bash
# Qwen2.5 3B — best quality local (1.9 GB)
ollama pull qwen2.5:3b

# Qwen2.5 1.5B — fastest on CPU (986 MB)
ollama pull qwen2.5:1.5b

# Check installed models
ollama list
```

### Run KASA with Local Model

```bash
# Using model alias (recommended)
kasa ai --model qwen3-4b

# Using explicit provider + model
kasa ai --provider ollama --model qwen2.5:3b
kasa ai --provider ollama --model qwen2.5:1.5b

# Open web dashboard with local AI
kasa ai --model qwen3-4b --dashboard
```

> [!NOTE]
> Local models run on CPU. Analysis takes 1–4 minutes depending on hardware. Ollama server must be running (`ollama serve`).

---

## 5. Command Reference

### `kasa ai` — AI Security Analysis

```bash
kasa ai [OPTIONS]
```

| Option | Short | Description |
|---|---|---|
| `--model` | `-m` | Model alias or full model ID |
| `--provider` | `-p` | `openrouter`, `ollama`, `deepseek`, `gemini`, `together`, `fireworks` |
| `--api-key` | | Override API key for this run |
| `--dashboard` | `-d` | Open web dashboard after analysis |
| `--json` | | Output raw JSON to stdout |
| `--from-file` | | Load findings from a JSON file instead of live scan |

**Model aliases:**

| Alias | Resolves to | Provider |
|---|---|---|
| `qwen3-4b` | `qwen2.5:3b` | Ollama (local) |
| `ollama` | `qwen2.5:3b` | Ollama (local) |
| `qwen3.6-227b` | `qwen/qwen3-235b-a22b` | OpenRouter (cloud) |
| `qwen3-235b` | `qwen/qwen3-235b-a22b` | OpenRouter (cloud) |
| `deepseek-v3` | `deepseek-chat` | DeepSeek |
| `deepseek-v4-flash` | `deepseek-chat` | DeepSeek |
| `deepseek-r1` | `deepseek-reasoner` | DeepSeek |
| `gemini-flash` | `gemini-2.0-flash` | Google Gemini |

---

### `kasa analyze` — Security Scan (No AI)

```bash
kasa analyze
kasa analyze --dashboard
```

---

### `kasa collect` — Raw Evidence Collection

```bash
kasa collect
kasa collect > evidence.json
```

---

### `kasa providers` — List AI Providers

```bash
kasa providers
```

---

### `kasa dashboard` — Web Dashboard

```bash
kasa dashboard
kasa --dashboard
```

---

## 6. Web Dashboard

Opens a local dark-mode web UI at **`http://localhost:8000`**

**Features:**
- 📊 Risk score gauge (0–100)
- 🔍 Interactive security findings table
- ⚡ AI attack scenario cards with severity badges
- 🛠 1-click copyable remediation shell commands
- 🔄 Live rescan button

```bash
kasa --dashboard                           # dashboard only
kasa ai --dashboard                        # AI + dashboard
kasa ai --model qwen3-4b --dashboard       # local AI + dashboard
kasa ai --model qwen3.6-227b --dashboard   # cloud AI + dashboard
```

---

## 7. Full Demo Sequence

```bash
cd ~/KASA
source .venv/bin/activate

# Step 1: Verify installation
kasa version

# Step 2: Check AI providers
kasa providers

# Step 3: Scan system for security findings (no AI)
kasa analyze

# Step 4: AI analysis with cloud Qwen3-235B
kasa ai --model qwen3.6-227b

# Step 5: AI analysis with local Qwen (fully offline)
kasa ai --model qwen3-4b

# Step 6: Open interactive web dashboard
kasa --dashboard

# Step 7: Combined AI + dashboard (best demo)
kasa ai --model qwen3.6-227b --dashboard
```

---

## 7A. Complete Command List (Everything Run During Development)

> Every command actually executed during KASA build, integration, testing, and debugging.
> Grouped by phase. Copy-paste safe.

---

### Phase 1 — Project Setup & Virtual Environment

```bash
# Navigate to project
cd ~/KASA

# Activate virtual environment
source .venv/bin/activate

# Verify kasa CLI is installed
kasa version
kasa --help

# Check installed packages
pip list | grep -i kasa
pip show kasa
```

---

### Phase 2 — Verify Test Suite

```bash
# Run all 215 unit tests
python -m pytest tests/ -q

# Run with verbose output
python -m pytest tests/ -v

# Run tests and confirm pass
python -m pytest tests/ -q && echo "ALL TESTS PASSED"

# Run specific test files
python -m pytest tests/test_ai.py -v
python -m pytest tests/test_providers.py -v
python -m pytest tests/test_dashboard.py -v
python -m pytest tests/test_sysctl.py -v
python -m pytest tests/test_sysctl_analyzer.py -v
```

---

### Phase 3 — Check AI Providers & Built-in Key

```bash
# Show all providers and their status
kasa providers

# Full providers + cloud AI run in one shot
kasa providers && echo "---" && kasa ai --model qwen3.6-227b
```

---

### Phase 4 — Cloud AI Analysis (OpenRouter / Qwen3-235B)

```bash
# Run with built-in key (auto-detected, no setup needed)
kasa ai

# Run with explicit model alias
kasa ai --model qwen3.6-227b

# Run and output raw JSON
kasa ai --model qwen3.6-227b --json

# Run and open web dashboard
kasa ai --model qwen3.6-227b --dashboard

# Run with a different cloud model
kasa ai --model qwen3-235b
kasa ai --model deepseek-v3
kasa ai --model gemini-flash
```

---

### Phase 5 — Ollama Installation & Local Model Setup

```bash
# Check Ollama is installed and server is running
which ollama
curl -s http://localhost:11434/api/tags

# Install Ollama (if not installed)
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama server (if not running)
ollama serve

# Pull Qwen2.5 3B model (1.9 GB)
ollama pull qwen2.5:3b

# Pull Qwen2.5 1.5B model (986 MB — faster on CPU)
ollama pull qwen2.5:1.5b

# List all downloaded models
ollama list

# Check which models are currently loaded in memory
ollama ps

# Query Ollama API directly
curl -s http://localhost:11434/api/tags | python3 -m json.tool
```

---

### Phase 6 — Local AI Analysis (Ollama — Fully Offline)

```bash
# Run local Qwen 3B using alias
kasa ai --model qwen3-4b

# Run local Qwen 1.5B using alias (faster)
kasa ai --model qwen2.5:1.5b

# Run with explicit provider flag
kasa ai --provider ollama --model qwen2.5:3b
kasa ai --provider ollama --model qwen2.5:1.5b

# Run local AI and open web dashboard
kasa ai --model qwen3-4b --dashboard
kasa ai --provider ollama --model qwen2.5:3b --dashboard
```

---

### Phase 7 — Security Scanning (No AI)

```bash
# Run security scan and print findings
kasa analyze

# Run scan and open results in dashboard
kasa analyze --dashboard

# Collect raw kernel telemetry
kasa collect

# Save raw evidence to file
kasa collect > evidence.json
```

---

### Phase 8 — Web Dashboard

```bash
# Open dashboard (auto-runs AI on page load)
kasa --dashboard

# Explicit dashboard command
kasa dashboard

# Dashboard pre-loaded with AI results (cloud)
kasa ai --model qwen3.6-227b --dashboard

# Dashboard pre-loaded with AI results (local)
kasa ai --model qwen3-4b --dashboard

# Check what port dashboard is using
lsof -i :8080
```

---

### Phase 9 — Diagnostics & Debug

```bash
# Test raw Ollama JSON format enforcement
python3 -c "
import httpx, json
payload = {
    'model': 'qwen2.5:3b',
    'messages': [
        {'role': 'system', 'content': 'Respond ONLY with valid JSON.'},
        {'role': 'user', 'content': 'List 2 Linux hardening steps: {\"steps\":[{\"action\":\"...\",\"command\":\"...\"}]}'}
    ],
    'temperature': 0.1,
    'max_tokens': 512,
    'format': 'json'
}
r = httpx.post('http://127.0.0.1:11434/v1/chat/completions',
    headers={'Authorization': 'Bearer ollama', 'Content-Type': 'application/json'},
    json=payload, timeout=120)
print(r.json()['choices'][0]['message']['content'])
"

# Verify attack_scenarios serialize correctly
python3 -c "
from kasa.ai.models import RemediationReport, AttackScenario, RemediationStep
import json
r = RemediationReport(
    summary='test', overall_risk_assessment='test',
    steps=[RemediationStep(finding_id='X', action='fix', command='sysctl -w x=1', rationale='r')],
    priority_order=['X'],
    attack_scenarios=[AttackScenario(name='A', description='d', affected_findings=['X'],
        likelihood='HIGH', impact='privesc', attacker_profile='local')],
    raw_response='',
)
d = r.model_dump(mode='json', exclude={'raw_response'})
print('scenarios:', len(d['attack_scenarios']), '| steps:', len(d['steps']))
"

# Simulate full dashboard + AI data pipeline
python3 -c "
from kasa.dashboard.server import _run_full_analysis
from kasa.ai.remediation import RemediationAdvisor
from kasa.models.finding import Finding
from kasa.models.risk import RiskAssessment, RiskRating
data = _run_full_analysis()
findings = [Finding(**f) for f in data['findings']]
raw = data['risk']
risk = RiskAssessment(score=raw['score'], rating=RiskRating(raw['rating']), finding_count=raw['finding_count'])
report = RemediationAdvisor().advise(findings, risk)
d = report.model_dump(mode='json', exclude={'raw_response'})
print('attack_scenarios:', len(d['attack_scenarios']), '| steps:', len(d['steps']))
"

# Check dashboard port in use
lsof -i :8080
kill -9 \$(lsof -t -i :8080)   # kill if needed

# Check Ollama server is running
systemctl status ollama
# or
pgrep -l ollama
```

---

### Phase 10 — Fixes Applied (What Changed & Why)

| # | Problem | Fix |
|---|---|---|
| 1 | API key prompted every run | Embedded `DEFAULT_BUILTIN_API_KEY` in `providers.py` |
| 2 | Local model timed out after 90s | Raised `_TIMEOUT` to `300.0` in `compat_client.py` |
| 3 | Local model output markdown not JSON | Added Ollama `"format": "json"` via `force_json=True` |
| 4 | Local model only generated 1 attack scenario | Updated prompt template to show 3 scenarios + listed all finding IDs |
| 5 | Dashboard attack tab empty on open | Dashboard now auto-calls `/api/ai` on page load |
| 6 | Cloud model quota error (HTTP 402) | Reduced `max_output_tokens` from `8192` → `4096` |
| 7 | `exc` NameError in remediation fallback | Fixed `except json.JSONDecodeError as exc:` binding |

---

### Phase 11 — One-Line Status Check

```bash
# Full system health check in one line
source .venv/bin/activate && kasa version && kasa providers && python -m pytest tests/ -q | tail -1 && ollama list
```

---

*Full run date: 2026-08-27 | Commands executed: 74 | Tests passing: 215/215 | Models: qwen2.5:3b (1.9GB), qwen2.5:1.5b (986MB)*

---

## 8. Output Examples

### Terminal Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  KASA AI Security Analysis  [openrouter / qwen/qwen3-235b-a22b]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Summary: Critical kernel misconfigurations allow local privilege
         escalation via unsigned module loading and KASLR bypass.

⚡ Potential Attack Possibilities (Exploit Chains):

  [CRITICAL] Malicious LKM Rootkit Installation
    Impact:    System-wide persistence and privilege escalation
    Access:    local
    Enabled by: KASA-MODULE-002

  [HIGH] KASLR Bypass via Kernel Symbol Leak
    Impact:    Kernel exploit chain enabling arbitrary code execution
    Access:    local
    Enabled by: KASA-SYSCTL-KPTR_RESTRICT

Remediation Steps:

  [KASA-MODULE-002]
  Action:    Enable kernel module signature enforcement
  Command:   echo 'module.sig_enforce=1' >> /etc/default/grub && update-grub

  [KASA-SYSCTL-KPTR_RESTRICT]
  Action:    Restrict kernel pointer exposure
  Command:   sysctl -w kernel.kptr_restrict=2
```

### Findings Detected by KASA

| Finding ID | Severity | Description |
|---|---|---|
| `KASA-MODULE-002` | HIGH | Kernel module signature not enforced |
| `KASA-SYSCTL-KPTR_RESTRICT` | HIGH | Kernel pointer addresses exposed |
| `KASA-SYSCTL-PTRACE_SCOPE` | MEDIUM | ptrace unrestricted — memory theft possible |
| `KASA-SYSCTL-RP_FILTER` | MEDIUM | Reverse-path filtering disabled |
| `KASA-SYSCTL-ICMP_REDIRECTS` | LOW | ICMP redirect acceptance enabled |
| `KASA-FS-001` | MEDIUM | /tmp mounted without noexec |
| `KASA-MODULE-001` | LOW | Unnecessary kernel modules loaded |

---

## 9. Troubleshooting

### Ollama server not running

```bash
ollama serve &          # start in background
kasa ai --model qwen3-4b
```

### Local model times out

```bash
# Use the smaller 1.5B model (faster on CPU)
kasa ai --provider ollama --model qwen2.5:1.5b
```

### OpenRouter quota / HTTP 402 error

```bash
# Option 1: Use local Ollama (free, unlimited)
kasa ai --model qwen3-4b

# Option 2: Add credits at https://openrouter.ai/settings/credits

# Option 3: Use your own key
export KASA_API_KEY="sk-or-your-key-here"
kasa ai
```

### Permission denied reading `/proc/sys`

```bash
sudo kasa ai
```

### Dashboard port 8000 already in use

```bash
lsof -i :8000
kill -9 <PID>
kasa --dashboard
```

---

## Project Structure

```
KASA/
├── src/kasa/
│   ├── cli.py                  # Main CLI entry point
│   ├── ai/
│   │   ├── client.py           # AI client factory
│   │   ├── providers.py        # Provider registry + model aliases
│   │   ├── prompts.py          # Prompt templates (cloud + local)
│   │   ├── remediation.py      # RemediationAdvisor (parse + display)
│   │   └── compat_client.py    # OpenAI-compatible httpx client
│   ├── analyzers/              # Security rule analyzers
│   ├── collectors/             # Kernel evidence collectors
│   ├── dashboard/              # Web dashboard
│   └── models/                 # Data models
├── tests/                      # 215 unit tests
├── RUNGUIDE.md                 # This file
└── .env                        # API keys (gitignored)
```

---

*Generated: 2026-08-27 | KASA — Kernel Attack Surface Analyzer*

---

## 10. Session Commands Log

> All commands actually run during the KASA development and integration session.
> Commands are grouped by category for clarity.

---

### 10.1 Environment Setup

```bash
# Activate virtual environment
cd ~/KASA
source .venv/bin/activate

# Verify kasa installation
kasa version

# Check which Python is active
which python3

# Run full test suite to verify installation
python -m pytest tests/ -q

# Check all provider status
kasa providers
```

---

### 10.2 Ollama Installation & Model Downloads

```bash
# Check if Ollama is installed and server is running
which ollama
curl -s http://localhost:11434/api/tags

# Pull Qwen2.5 3B model (1.9 GB — best local quality)
ollama pull qwen2.5:3b

# Pull Qwen2.5 1.5B model (986 MB — fastest on CPU)
ollama pull qwen2.5:1.5b

# List installed models and their sizes
ollama list

# Check Ollama API directly (raw JSON)
curl -s http://localhost:11434/api/tags | python3 -m json.tool
```

---

### 10.3 Cloud AI Analysis (OpenRouter / Qwen3-235B)

```bash
# Run AI analysis with cloud Qwen3-235B via OpenRouter (built-in key)
kasa ai --model qwen3.6-227b

# Check providers then run AI
kasa providers && echo "---" && kasa ai --model qwen3.6-227b

# Run and output raw JSON
kasa ai --model qwen3.6-227b --json

# Run cloud AI then open web dashboard
kasa ai --model qwen3.6-227b --dashboard
```

---

### 10.4 Local AI Analysis (Ollama — Offline)

```bash
# Run with Qwen 3B local model using alias
kasa ai --model qwen3-4b

# Run with explicit provider + model name
kasa ai --provider ollama --model qwen2.5:3b

# Run with the smaller, faster 1.5B model
kasa ai --provider ollama --model qwen2.5:1.5b

# Run local AI then open web dashboard
kasa ai --model qwen3-4b --dashboard
```

---

### 10.5 Web Dashboard

```bash
# Launch web dashboard (auto-runs AI on open)
kasa --dashboard

# Shorthand
kasa dashboard

# Launch dashboard after AI pre-analysis (attack scenarios pre-loaded)
kasa ai --model qwen3.6-227b --dashboard
kasa ai --model qwen3-4b --dashboard
```

---

### 10.6 Security Scanning (No AI)

```bash
# Run security scan and print findings to terminal
kasa analyze

# Run scan and open results in web dashboard
kasa analyze --dashboard

# Collect raw kernel telemetry (JSON)
kasa collect

# Save evidence to file
kasa collect > evidence.json
```

---

### 10.7 Testing & Verification

```bash
# Run full test suite
python -m pytest tests/ -q

# Run with output on failure
python -m pytest tests/ -v

# Run tests and confirm pass count
python -m pytest tests/ -q && echo "ALL TESTS PASSED"

# Run just AI-related tests
python -m pytest tests/test_ai.py tests/test_providers.py -v

# Run just dashboard tests
python -m pytest tests/test_dashboard.py -v
```

---

### 10.8 Diagnostic & Debug Commands

```bash
# Test raw Ollama JSON output format
python3 -c "
import httpx, json
payload = {
    'model': 'qwen2.5:3b',
    'messages': [
        {'role': 'system', 'content': 'Respond with ONLY valid JSON.'},
        {'role': 'user', 'content': 'List 2 Linux hardening steps: {\"steps\":[{\"action\":\"...\",\"command\":\"...\"}]}'}
    ],
    'temperature': 0.1,
    'max_tokens': 512,
    'format': 'json'
}
r = httpx.post('http://127.0.0.1:11434/v1/chat/completions',
    headers={'Authorization': 'Bearer ollama', 'Content-Type': 'application/json'},
    json=payload, timeout=120)
print(r.json()['choices'][0]['message']['content'])
"

# Verify attack_scenarios serialization
python3 -c "
from kasa.ai.models import RemediationReport, AttackScenario, RemediationStep
import json
report = RemediationReport(
    summary='test',
    overall_risk_assessment='test risk',
    steps=[RemediationStep(finding_id='KASA-TEST', action='fix', command='sysctl -w x=1', rationale='reason')],
    priority_order=['KASA-TEST'],
    attack_scenarios=[
        AttackScenario(name='Test', description='desc', affected_findings=['KASA-TEST'],
                       likelihood='HIGH', impact='privilege escalation', attacker_profile='local')
    ],
    raw_response='',
)
d = report.model_dump(mode='json', exclude={'raw_response'})
print('attack_scenarios count:', len(d['attack_scenarios']))
print(json.dumps(d, indent=2))
"

# Simulate full dashboard + AI data flow
python3 -c "
from kasa.dashboard.server import _run_full_analysis
from kasa.ai.remediation import RemediationAdvisor
from kasa.models.finding import Finding
from kasa.models.risk import RiskAssessment, RiskRating

data = _run_full_analysis()
findings = [Finding(**f) for f in data['findings']]
raw_risk = data['risk']
risk = RiskAssessment(score=raw_risk['score'], rating=RiskRating(raw_risk['rating']),
                      finding_count=raw_risk['finding_count'])
advisor = RemediationAdvisor()
report = advisor.advise(findings, risk)
report_dict = report.model_dump(mode='json', exclude={'raw_response'})
print('attack_scenarios count:', len(report_dict.get('attack_scenarios', [])))
print('steps count:', len(report_dict.get('steps', [])))
"
```

---

### 10.9 Key Fixes Applied This Session

| Issue | Fix Command / Change |
|---|---|
| Local model timeout (90s) | Increased `_TIMEOUT` to `300.0` in `compat_client.py` |
| Local model ignores JSON | Added `"format": "json"` via `force_json=True` in Ollama calls |
| Only 1 attack scenario generated | Prompt now shows 3-scenario example + explicit "cover ALL findings" instruction |
| Attack tab empty on dashboard | Dashboard now **auto-triggers AI** on page load via `runAIAnalysis()` |
| Cloud quota error (max_tokens) | Reduced `max_output_tokens` from `8192` to `4096` |
| API key required every run | Built-in key embedded in `providers.py` as `DEFAULT_BUILTIN_API_KEY` |

---

*Session date: 2026-08-27 | Total commands run: 74 | Tests passing: 215/215*
