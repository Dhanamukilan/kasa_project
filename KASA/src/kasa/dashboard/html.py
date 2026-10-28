"""Modern, self-contained HTML/CSS/JS template for the KASA Web Dashboard."""

from __future__ import annotations

import json
from typing import Any


def render_dashboard_html(initial_data: dict[str, Any]) -> str:
    """Generate a self-contained single-page web dashboard."""
    json_payload = json.dumps(initial_data).replace("</script>", "<\\/script>")

    return f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>KASA — Linux Kernel Attack Surface Dashboard</title>
  <style>
    :root {{
      --bg-main: #0b0f19;
      --bg-card: #111827;
      --bg-card-hover: #1f2937;
      --border-color: #1e293b;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --sev-critical: #ef4444;
      --sev-high: #f97316;
      --sev-medium: #eab308;
      --sev-low: #3b82f6;
      --sev-info: #6b7280;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-main);
      color: var(--text-main);
      line-height: 1.5;
      padding-bottom: 40px;
    }}
    .header {{
      background-color: rgba(17, 24, 39, 0.95);
      backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--border-color);
      padding: 16px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }}
    .logo-group {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .logo-badge {{
      background: linear-gradient(135deg, #06b6d4, #3b82f6);
      color: #fff;
      font-weight: 800;
      font-size: 14px;
      padding: 4px 10px;
      border-radius: 6px;
      letter-spacing: 1px;
    }}
    .logo-title {{
      font-size: 18px;
      font-weight: 700;
      color: #fff;
    }}
    .header-actions {{
      display: flex;
      gap: 10px;
      align-items: center;
    }}
    .btn {{
      background-color: #1f2937;
      color: #fff;
      border: 1px solid var(--border-color);
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }}
    .btn:hover {{
      background-color: #374151;
      border-color: #4b5563;
    }}
    .btn-primary {{
      background: linear-gradient(135deg, #0891b2, #2563eb);
      border: none;
    }}
    .btn-primary:hover {{
      background: linear-gradient(135deg, #06b6d4, #3b82f6);
    }}
    .container {{
      max-width: 1360px;
      margin: 0 auto;
      padding: 24px;
    }}
    .grid-stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .stat-card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .stat-title {{
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      margin-bottom: 8px;
    }}
    .stat-val-group {{
      display: flex;
      align-items: baseline;
      gap: 10px;
    }}
    .stat-value {{
      font-size: 28px;
      font-weight: 800;
      color: #fff;
    }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .badge-critical {{ background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-high {{ background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
    .badge-medium {{ background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }}
    .badge-low {{ background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-info {{ background-color: rgba(107, 114, 128, 0.2); color: #9ca3af; border: 1px solid rgba(107, 114, 128, 0.4); }}

    .tabs {{
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border-color);
      margin-bottom: 24px;
    }}
    .tab-btn {{
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      font-weight: 600;
      padding: 12px 18px;
      cursor: pointer;
      position: relative;
      transition: color 0.2s;
    }}
    .tab-btn.active {{
      color: var(--accent-cyan);
    }}
    .tab-btn.active::after {{
      content: '';
      position: absolute;
      bottom: -1px;
      left: 0;
      right: 0;
      height: 2px;
      background-color: var(--accent-cyan);
    }}
    .tab-content {{
      display: none;
    }}
    .tab-content.active {{
      display: block;
    }}

    .section-card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 20px;
    }}
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }}
    .section-title {{
      font-size: 16px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    /* Attack Scenarios Cards */
    .attack-card {{
      background-color: #131d2e;
      border: 1px solid #1e3a8a;
      border-left: 4px solid #ef4444;
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 14px;
    }}
    .attack-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }}
    .attack-name {{
      font-size: 15px;
      font-weight: 700;
      color: #f87171;
    }}
    .attack-desc {{
      font-size: 13.5px;
      color: #d1d5db;
      margin-bottom: 12px;
      line-height: 1.6;
    }}
    .attack-tags {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }}
    .tag {{
      background-color: #1f2937;
      color: #9ca3af;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-family: monospace;
    }}

    /* Finding Items */
    .finding-item {{
      background-color: #161e2e;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
      transition: border-color 0.2s;
    }}
    .finding-item:hover {{
      border-color: #374151;
    }}
    .finding-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 8px;
    }}
    .finding-title {{
      font-size: 14.5px;
      font-weight: 700;
      color: #fff;
    }}
    .finding-id {{
      font-family: monospace;
      font-size: 12px;
      color: var(--accent-cyan);
      margin-right: 8px;
    }}
    .finding-desc {{
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 10px;
    }}
    .finding-rec {{
      background-color: rgba(6, 182, 212, 0.08);
      border-left: 3px solid var(--accent-cyan);
      padding: 8px 12px;
      border-radius: 0 4px 4px 0;
      font-size: 12.5px;
      color: #e0f2fe;
    }}

    /* Remediation Steps */
    .step-card {{
      background-color: #161e2e;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
    }}
    .cmd-box {{
      background-color: #0b0f19;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 10px 14px;
      margin-top: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: "JetBrains Mono", Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      color: #38bdf8;
    }}
    .copy-btn {{
      background: #1e293b;
      border: 1px solid #334155;
      color: #cbd5e1;
      padding: 4px 8px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    }}
    .copy-btn:hover {{
      background: #334155;
      color: #fff;
    }}

    /* Table styles */
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th, td {{
      padding: 10px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border-color);
    }}
    th {{
      color: var(--text-muted);
      font-size: 11.5px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    tr:hover td {{
      background-color: var(--bg-card-hover);
    }}
    .search-input {{
      background-color: #0b0f19;
      border: 1px solid var(--border-color);
      color: #fff;
      padding: 7px 12px;
      border-radius: 6px;
      font-size: 13px;
      width: 260px;
    }}
    .search-input:focus {{
      outline: none;
      border-color: var(--accent-cyan);
    }}
  </style>
</head>
<body>

  <header class="header">
    <div class="logo-group">
      <span class="logo-badge">KASA</span>
      <span class="logo-title">Kernel Attack Surface Analyzer</span>
      <span style="color: #64748b; font-size: 13px;">| Dashboard</span>
    </div>
    <div class="header-actions">
      <button class="btn" onclick="exportJSON()">📥 Export JSON</button>
      <button class="btn" onclick="reScan()">🔄 Rescan System</button>
      <button class="btn btn-primary" onclick="runAIAnalysis()">✨ AI Attack & Remediation</button>
    </div>
  </header>

  <main class="container">

    <!-- Top Statistics Cards -->
    <div class="grid-stats">
      <div class="stat-card">
        <div class="stat-title">Overall Risk Score</div>
        <div class="stat-val-group">
          <span class="stat-value" id="risk-score">--</span>
          <span class="badge" id="risk-rating">--</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Security Findings</div>
        <div class="stat-val-group">
          <span class="stat-value" id="findings-count">--</span>
          <span style="font-size: 13px; color: var(--text-muted);" id="findings-breakdown"></span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Kernel & Architecture</div>
        <div style="font-size: 15px; font-weight: 700; color: #fff;" id="kernel-release">--</div>
        <div style="font-size: 12px; color: var(--text-muted);" id="kernel-arch">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Attack Surface Metrics</div>
        <div style="font-size: 13px; color: #cbd5e1; display: flex; flex-direction: column; gap: 2px;">
          <div>📦 <span id="metric-modules">--</span> Loaded Modules</div>
          <div>📂 <span id="metric-mounts">--</span> Active Mounts</div>
          <div>⚙️ <span id="metric-sysctl">--</span> Sysctl Parameters</div>
        </div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('tab-attacks')">🎯 Potential Attack Possibilities (AI)</button>
      <button class="tab-btn" onclick="switchTab('tab-findings')">🛡️ Security Findings (<span id="tab-findings-badge">0</span>)</button>
      <button class="tab-btn" onclick="switchTab('tab-remediation')">🔧 AI Remediation Plan</button>
      <button class="tab-btn" onclick="switchTab('tab-telemetry')">📊 Host Telemetry</button>
    </div>

    <!-- Tab 1: Attack Scenarios -->
    <div id="tab-attacks" class="tab-content active">
      <div class="section-card">
        <div class="section-header">
          <div class="section-title">⚡ AI-Identified Potential Attack Scenarios</div>
          <span style="font-size: 12px; color: var(--text-muted);">Real-world attack paths based on current kernel configuration & weaknesses</span>
        </div>
        <div id="attacks-list">
          <div id="attacks-loading" style="padding: 32px; text-align: center; color: var(--text-muted);">
            <div style="font-size: 28px; margin-bottom: 12px; animation: spin 1s linear infinite; display:inline-block;">⚙️</div>
            <div style="font-size: 15px; font-weight: 600; color: #e2e8f0; margin-bottom: 8px;">Running AI Analysis...</div>
            <div style="font-size: 13px; color: #9ca3af;">Scanning kernel findings and generating attack scenarios. This may take 1–3 minutes for local models.</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 2: Findings -->
    <div id="tab-findings" class="tab-content">
      <div class="section-card">
        <div class="section-header">
          <div class="section-title">📋 Normalized Security Findings</div>
          <input type="text" class="search-input" placeholder="Filter findings..." oninput="filterFindings(this.value)" />
        </div>
        <div id="findings-list"></div>
      </div>
    </div>

    <!-- Tab 3: Remediation -->
    <div id="tab-remediation" class="tab-content">
      <div class="section-card">
        <div class="section-header">
          <div class="section-title">🛠️ Actionable Hardening Steps</div>
          <span id="remediation-model-label" style="font-size: 12px; color: var(--accent-cyan);"></span>
        </div>
        <div id="remediation-summary" style="margin-bottom: 16px; font-size: 14px; color: #e2e8f0;"></div>
        <div id="steps-list"></div>
      </div>
    </div>

    <!-- Tab 4: Telemetry -->
    <div id="tab-telemetry" class="tab-content">
      <div class="section-card">
        <div class="section-header">
          <div class="section-title">⚙️ Security-Relevant Sysctl Inventory</div>
          <input type="text" class="search-input" placeholder="Search sysctl key..." oninput="filterTable('sysctl-table', this.value)" />
        </div>
        <table id="sysctl-table">
          <thead>
            <tr><th>Sysctl Key</th><th>Value</th><th>Status</th><th>Description</th></tr>
          </thead>
          <tbody id="sysctl-body"></tbody>
        </table>
      </div>

      <div class="section-card">
        <div class="section-header">
          <div class="section-title">📦 Loaded Kernel Modules</div>
          <input type="text" class="search-input" placeholder="Search modules..." oninput="filterTable('modules-table', this.value)" />
        </div>
        <table id="modules-table">
          <thead>
            <tr><th>Module Name</th><th>Size (Bytes)</th><th>Instances</th><th>Used By</th></tr>
          </thead>
          <tbody id="modules-body"></tbody>
        </table>
      </div>
    </div>

  </main>

  <script>
    let DATA = {json_payload};

    function renderDashboard(data) {{
      DATA = data;

      // Stats
      const risk = data.risk || {{ score: 0, rating: 'low' }};
      const scoreEl = document.getElementById('risk-score');
      const ratingEl = document.getElementById('risk-rating');
      scoreEl.innerText = risk.score;
      ratingEl.innerText = (risk.rating || 'low').toUpperCase();
      ratingEl.className = 'badge badge-' + (risk.rating || 'low');

      const findings = data.findings || [];
      document.getElementById('findings-count').innerText = findings.length;
      document.getElementById('tab-findings-badge').innerText = findings.length;

      const kernel = data.snapshot?.kernel?.kernel || {{}};
      document.getElementById('kernel-release').innerText = kernel.release || 'Linux';
      document.getElementById('kernel-arch').innerText = `${{kernel.machine || ''}} (${{kernel.version || ''}})`;

      const modules = data.snapshot?.modules?.loaded || [];
      const mounts = data.snapshot?.filesystems?.mounts || [];
      const sysctls = data.snapshot?.sysctl_params || [];
      document.getElementById('metric-modules').innerText = modules.length;
      document.getElementById('metric-mounts').innerText = mounts.length;
      document.getElementById('metric-sysctl').innerText = sysctls.length;

      // Render Findings
      renderFindings(findings);

      // Render AI Attack Scenarios & Remediation if available
      renderAIReport(data.ai_report);

      // Render Telemetry tables
      renderSysctlTable(sysctls);
      renderModulesTable(modules);
    }}

    function renderFindings(findings) {{
      const container = document.getElementById('findings-list');
      if (!findings.length) {{
        container.innerHTML = '<div style="padding:20px; color:#9ca3af;">No findings detected. System is well-hardened.</div>';
        return;
      }}
      container.innerHTML = findings.map(f => `
        <div class="finding-item" data-text="${{f.id}} ${{f.title}} ${{f.category}}">
          <div class="finding-top">
            <div>
              <span class="finding-id">${{f.id}}</span>
              <span class="finding-title">${{f.title}}</span>
            </div>
            <span class="badge badge-${{f.severity}}">${{f.severity.toUpperCase()}}</span>
          </div>
          <div class="finding-desc">${{f.description}}</div>
          ${{f.recommendation ? `<div class="finding-rec">💡 <strong>Fix:</strong> ${{f.recommendation}}</div>` : ''}}
        </div>
      `).join('');
    }}

    function renderAIReport(report) {{
      if (!report) return;

      // Attack Scenarios
      const attacksContainer = document.getElementById('attacks-list');
      const scenarios = report.attack_scenarios || [];
      if (scenarios.length > 0) {{
        attacksContainer.innerHTML = scenarios.map(a => `
          <div class="attack-card">
            <div class="attack-head">
              <span class="attack-name">⚠️ ${{a.name}}</span>
              <div style="display:flex; gap:6px;">
                <span class="badge badge-${{(a.likelihood || 'medium').toLowerCase()}}">Likelihood: ${{a.likelihood}}</span>
                <span class="badge" style="background:#374151; color:#f3f4f6;">Access: ${{a.attacker_profile}}</span>
              </div>
            </div>
            <div class="attack-desc">${{a.description}}</div>
            <div style="margin-bottom:8px; font-size:12.5px; color:#93c5fd;">
              💥 <strong>Impact:</strong> ${{a.impact}}
            </div>
            <div class="attack-tags">
              <span style="font-size:11px; color:#9ca3af;">Enabled by findings:</span>
              ${{(a.affected_findings || []).map(fid => `<span class="tag">${{fid}}</span>`).join('')}}
            </div>
          </div>
        `).join('');
      }} else {{
        attacksContainer.innerHTML = `
          <div style="padding: 24px; text-align: center; color: var(--text-muted);">
            <div style="font-size: 28px; margin-bottom: 10px;">⚠️</div>
            <div style="font-size: 15px; font-weight: 600; color: #e2e8f0; margin-bottom: 8px;">No Attack Scenarios Returned</div>
            <div style="font-size: 13px; max-width: 480px; margin: 0 auto; line-height: 1.6;">
              The AI analysis completed but did not generate attack scenarios.<br>
              This usually means the AI model (local/Ollama) couldn't follow the JSON schema.<br>
              <span style="color: var(--accent-cyan);">Try running with a cloud model:</span><br>
              <code style="background:#0b0f19; padding: 4px 8px; border-radius:4px; font-size:12px;">kasa ai --model qwen3.6-227b --dashboard</code>
            </div>
          </div>
        `;
      }}

      // Remediation Steps
      const stepsContainer = document.getElementById('steps-list');
      const summaryContainer = document.getElementById('remediation-summary');
      summaryContainer.innerHTML = `
        <p><strong>Executive Summary:</strong> ${{report.summary || ''}}</p>
        <p style="margin-top:6px; color:#94a3b8;">${{report.overall_risk_assessment || ''}}</p>
      `;

      const steps = report.steps || [];
      stepsContainer.innerHTML = steps.map(s => `
        <div class="step-card">
          <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
            <strong style="color:#38bdf8;">[${{s.finding_id}}] ${{s.action}}</strong>
          </div>
          <div style="font-size:13px; color:#9ca3af; margin-bottom:6px;">${{s.rationale}}</div>
          ${{s.command ? `
            <div class="cmd-box">
              <span>${{s.command}}</span>
              <button class="copy-btn" onclick="copyCmd(this, '${{s.command.replace(/'/g, "\\'")}}')">Copy</button>
            </div>
          ` : ''}}
        </div>
      `).join('');
    }}

    function renderSysctlTable(sysctls) {{
      const tbody = document.getElementById('sysctl-body');
      tbody.innerHTML = sysctls.map(s => `
        <tr>
          <td style="font-family:monospace; color:#38bdf8;">${{s.key.replace('sysctl.', '')}}</td>
          <td style="font-weight:600;">${{s.value !== null ? s.value : '<span style="color:#6b7280;">N/A</span>'}}</td>
          <td><span class="badge badge-${{s.status === 'available' ? 'low' : 'info'}}">${{s.status}}</span></td>
          <td style="color:#9ca3af;">${{s.source?.description || ''}}</td>
        </tr>
      `).join('');
    }}

    function renderModulesTable(modules) {{
      const tbody = document.getElementById('modules-body');
      tbody.innerHTML = modules.slice(0, 100).map(m => `
        <tr>
          <td style="font-family:monospace; color:#38bdf8;">${{m.name}}</td>
          <td>${{m.size.toLocaleString()}}</td>
          <td>${{m.instances}}</td>
          <td style="color:#9ca3af; font-size:12px;">${{(m.used_by || []).join(', ') || '-'}}</td>
        </tr>
      `).join('');
    }}

    function switchTab(tabId, btnElement) {{
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      let btn = btnElement || (window.event && window.event.target ? window.event.target.closest('.tab-btn') : null);
      if (!btn) {{
        btn = document.querySelector(`.tab-btn[onclick*="${{tabId}}"]`);
      }}
      if (btn) btn.classList.add('active');

      const content = document.getElementById(tabId);
      if (content) content.classList.add('active');
    }}

    function filterFindings(query) {{
      const q = query.toLowerCase();
      document.querySelectorAll('.finding-item').forEach(item => {{
        item.style.display = item.getAttribute('data-text').toLowerCase().includes(q) ? 'block' : 'none';
      }});
    }}

    function filterTable(tableId, query) {{
      const q = query.toLowerCase();
      document.querySelectorAll(`#${{tableId}} tbody tr`).forEach(row => {{
        row.style.display = row.innerText.toLowerCase().includes(q) ? '' : 'none';
      }});
    }}

    function copyCmd(btn, cmd) {{
      navigator.clipboard.writeText(cmd);
      btn.innerText = 'Copied!';
      setTimeout(() => btn.innerText = 'Copy', 2000);
    }}

    function exportJSON() {{
      const blob = new Blob([JSON.stringify(DATA, null, 2)], {{ type: 'application/json' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `kasa_security_report_${{Date.now()}}.json`;
      a.click();
    }}

    async function reScan() {{
      try {{
        const res = await fetch('/api/scan');
        const data = await res.json();
        renderDashboard(data);
      }} catch (err) {{
        alert('Rescan error: ' + err);
      }}
    }}

    async function runAIAnalysis() {{
      // Show loading state
      const attacksContainer = document.getElementById('attacks-list');
      attacksContainer.innerHTML = `
        <div style="padding: 32px; text-align: center; color: var(--text-muted);">
          <div style="font-size: 32px; margin-bottom: 12px;">⚙️</div>
          <div style="font-size: 15px; font-weight: 600; color: #e2e8f0; margin-bottom: 8px;">Running AI Analysis...</div>
          <div style="font-size: 13px; color: #9ca3af; max-width: 420px; margin: 0 auto;">
            Analysing kernel findings with AI. This takes ~30 seconds for cloud models,
            or 1–4 minutes for local Ollama models.
          </div>
        </div>`;

      const stepsContainer = document.getElementById('steps-list');
      if (stepsContainer) stepsContainer.innerHTML = '<div style="padding:20px; color:#9ca3af;">Running AI analysis...</div>';

      try {{
        const res = await fetch('/api/ai');
        const data = await res.json();
        if (data.error) {{
          attacksContainer.innerHTML = `
            <div style="padding: 24px; text-align: center; color: #ef4444;">
              <div style="font-size: 28px; margin-bottom: 10px;">❌</div>
              <div style="font-weight: 600; margin-bottom: 8px;">AI Analysis Failed</div>
              <div style="font-size: 13px; color: #9ca3af;">${{data.error}}</div>
            </div>`;
          return;
        }}
        DATA.ai_report = data;
        renderAIReport(data);
        switchTab('tab-attacks');
      }} catch (err) {{
        attacksContainer.innerHTML = `
          <div style="padding: 24px; text-align: center; color: #ef4444;">
            <div style="font-size: 28px; margin-bottom: 10px;">❌</div>
            <div style="font-weight: 600; margin-bottom: 8px;">Connection Error</div>
            <div style="font-size: 13px; color: #9ca3af;">${{err}}</div>
          </div>`;
      }}
    }}

    // Initial render
    renderDashboard(DATA);

    // Auto-trigger AI if not pre-loaded
    if (!DATA.ai_report) {{
      runAIAnalysis();
    }}
  </script>
</body>
</html>
"""
