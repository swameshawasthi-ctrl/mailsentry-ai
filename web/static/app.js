document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const emailInput = document.getElementById("email-input");
    const btnAnalyze = document.getElementById("btn-analyze");
    const btnClear = document.getElementById("btn-clear");
    const btnLoadPhish = document.getElementById("btn-load-phish");
    const btnLoadHeaders = document.getElementById("btn-load-headers");
    const btnLoadClean = document.getElementById("btn-load-clean");
    const btnRefreshHistory = document.getElementById("btn-refresh-history");
    const btnExportReport = document.getElementById("btn-export-report");
    const btnExportLog = document.getElementById("btn-export-log");

    const resultsPanel = document.getElementById("results-panel");
    const resSeverityBadge = document.getElementById("res-severity-badge");
    const resIncidentId = document.getElementById("res-incident-id");
    const resScore = document.getElementById("res-score");
    const resScoreBar = document.getElementById("res-score-bar");
    const resCategory = document.getElementById("res-category");
    const resSender = document.getElementById("res-sender");
    const resEvidenceList = document.getElementById("res-evidence-list");
    const resReasoningText = document.getElementById("res-reasoning-text");
    const resActionList = document.getElementById("res-action-list");

    const authSpf = document.getElementById("auth-spf");
    const authDkim = document.getElementById("auth-dkim");
    const authMx = document.getElementById("auth-mx");

    const statTotal = document.getElementById("stat-total");
    const statCritical = document.getElementById("stat-critical");
    const statSafe = document.getElementById("stat-safe");
    const statRate = document.getElementById("stat-rate");
    const historyTbody = document.getElementById("history-tbody");

    const scanModal = document.getElementById("scan-modal");
    const modalClose = document.getElementById("modal-close");
    const modalBackdrop = document.getElementById("modal-backdrop");
    const modalBody = document.getElementById("modal-body");

    let currentReport = null;
    let cachedScans = [];

    // Real-world Enterprise Samples
    const SAMPLE_PHISHING = `From: Security Notifications <security@paypa1-support.com>
To: target.executive@enterprise.com
Subject: URGENT: Corporate PayPal Account Scheduled for Termination in 30 Minutes

Dear Security Team,

We detected multiple unauthorized login requests originating from unfamiliar IP addresses in Moscow, Russia.
In accordance with Enterprise Security Compliance, your corporate master account will be locked within 30 minutes.

Confirm credential authorization immediately via our secure administrative gateway:
https://paypa1-support.com/auth-verify?token=894102941

Failure to verify will trigger permanent deactivation of financial disbursements.

Sincerely,
PayPal Incident Response Operations`;

    const SAMPLE_HEADERS = `Received: from mail-relay.phishingnet.ru ([185.220.101.5]) by gateway.enterprise.com; Fri, 23 Oct 2026 14:10:02 +0000
Received-SPF: fail (enterprise.com: domain of support@micros0ft-login.xyz does not designate 185.220.101.5 as permitted sender)
Authentication-Results: dkim=fail header.d=micros0ft-login.xyz; dmarc=reject
From: Microsoft 365 Cloud Admin <support@micros0ft-login.xyz>
To: soc.triage@enterprise.com
Subject: CRITICAL: Immediate Enterprise Password Expiration Alert

Your 365 Enterprise administrative account password expires in 15 minutes.
Reset your administrative credentials immediately to prevent directory lockout:
https://micros0ft-login.xyz/portal/admin-auth`;

    const SAMPLE_CLEAN = `Received: from mail-pj1.google.com ([209.85.216.50]) by gateway.enterprise.com; Fri, 23 Oct 2026 14:15:22 +0000
Received-SPF: pass (enterprise.com: domain of notifications@calendar.google.com designates 209.85.216.50 as permitted sender)
Authentication-Results: dkim=pass header.d=google.com; dmarc=pass
From: Google Calendar <notifications@calendar.google.com>
To: engineering.leads@enterprise.com
Subject: Meeting Reminder: Sprint Architecture Review at 4:00 PM

Hi Engineering Team,

This is a scheduled reminder for your Sprint Architecture Review meeting today at 4:00 PM IST.
Join Google Meet Session:
https://meet.google.com/xyz-abcd-efg

Best regards,
Google Workspace Operations`;

    // Presets
    btnLoadPhish.addEventListener("click", () => {
        emailInput.value = SAMPLE_PHISHING;
        emailInput.focus();
    });

    btnLoadHeaders.addEventListener("click", () => {
        emailInput.value = SAMPLE_HEADERS;
        emailInput.focus();
    });

    btnLoadClean.addEventListener("click", () => {
        emailInput.value = SAMPLE_CLEAN;
        emailInput.focus();
    });

    btnClear.addEventListener("click", () => {
        emailInput.value = "";
        resultsPanel.style.display = "none";
        emailInput.focus();
    });

    // Run Forensic Analysis
    async function runAnalysis() {
        const text = emailInput.value.trim();
        if (!text) {
            alert("Please paste email content or RFC headers to execute forensics.");
            return;
        }

        btnAnalyze.disabled = true;
        btnAnalyze.innerHTML = `<span>Investigating Payload...</span>`;

        try {
            const resp = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ raw_text: text, source: "enterprise_soc" })
            });

            if (!resp.ok) throw new Error("Analysis failed");
            const data = await resp.json();
            currentReport = data;

            // Show Dossier
            resultsPanel.style.display = "block";
            const incidentId = "INC-2026-" + Math.floor(1000 + Math.random() * 9000);
            resIncidentId.textContent = `INCIDENT ID: ${incidentId}`;

            // Score and Bar
            const score = data.risk_score;
            resScore.textContent = score;
            resScoreBar.style.width = `${score}%`;

            if (score >= 80) {
                resScoreBar.style.background = "var(--color-danger)";
                resultsPanel.className = "card panel-results";
                resSeverityBadge.className = "severity-badge";
                resSeverityBadge.textContent = "CRITICAL THREAT (SEV-1)";
            } else if (score >= 40) {
                resScoreBar.style.background = "var(--color-warning)";
                resultsPanel.className = "card panel-results warning";
                resSeverityBadge.className = "severity-badge suspicious";
                resSeverityBadge.textContent = "SUSPICIOUS (SEV-2)";
            } else {
                resScoreBar.style.background = "var(--color-success)";
                resultsPanel.className = "card panel-results safe";
                resSeverityBadge.className = "severity-badge safe";
                resSeverityBadge.textContent = "CLEAN BASELINE (SEV-4)";
            }

            resCategory.textContent = data.attack_category;
            resSender.textContent = data.sender_email || "Unknown";

            // Auth Matrix Evaluation
            const evString = JSON.stringify(data.evidence || []);
            if (evString.includes("SPF Authentication FAILED")) {
                authSpf.className = "status-tag fail";
                authSpf.textContent = "FAIL";
            } else if (text.includes("Received-SPF: pass")) {
                authSpf.className = "status-tag pass";
                authSpf.textContent = "PASS";
            } else {
                authSpf.className = "status-tag neutral";
                authSpf.textContent = "NOT ENFORCED";
            }

            if (evString.includes("DKIM Cryptographic Signature Invalid") || evString.includes("DKIM Signing Domain")) {
                authDkim.className = "status-tag fail";
                authDkim.textContent = "INVALID";
            } else if (text.includes("dkim=pass")) {
                authDkim.className = "status-tag pass";
                authDkim.textContent = "VERIFIED";
            } else {
                authDkim.className = "status-tag neutral";
                authDkim.textContent = "ABSENT";
            }

            if (evString.includes("lacks valid MX records")) {
                authMx.className = "status-tag fail";
                authMx.textContent = "NO MX";
            } else {
                authMx.className = "status-tag pass";
                authMx.textContent = "VALID";
            }

            // Evidence List
            resEvidenceList.innerHTML = "";
            (data.evidence || []).forEach(item => {
                const li = document.createElement("li");
                li.innerHTML = item.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
                if (score < 30) li.classList.add("clean");
                resEvidenceList.appendChild(li);
            });

            // Reasoning Note
            resReasoningText.textContent = data.analyst_reasoning || "Evaluation completed against baseline policies.";

            // Actions List
            resActionList.innerHTML = "";
            (data.recommendations || []).forEach(item => {
                const li = document.createElement("li");
                li.textContent = item.replace(/^[•\s\*\-]+/, "").replace(/[🚫🔒🌐🛡️🗑️✅💡]/g, "").trim();
                resActionList.appendChild(li);
            });

            // Scroll to dossier
            resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });

            // Refresh logs
            loadStats();
            loadHistory();
        } catch (err) {
            alert("Error running investigation: " + err.message);
        } finally {
            btnAnalyze.disabled = false;
            btnAnalyze.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20"/><path d="m17 5-5-3-5 3"/><path d="m17 19-5 3-5-3"/><path d="M2 12h20"/><path d="m5 7-3 5 3 5"/><path d="m19 7 3 5-3 5"/></svg>
                <span>Execute Forensics</span>
            `;
        }
    }

    btnAnalyze.addEventListener("click", runAnalysis);

    // Export JSON
    btnExportReport.addEventListener("click", () => {
        if (!currentReport) return;
        const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `incident-dossier-${Date.now()}.json`;
        a.click();
    });

    // Export CSV Log
    btnExportLog.addEventListener("click", () => {
        if (!cachedScans || cachedScans.length === 0) {
            alert("No incident records available to export.");
            return;
        }
        let csv = "ID,Timestamp,Sender,Subject,Category,RiskScore,Severity,OriginIP,Source\n";
        cachedScans.forEach(s => {
            csv += `"${s.id}","${s.created_at}","${s.sender_email || ''}","${(s.subject || '').replace(/"/g, '""')}","${s.attack_category}","${s.risk_score}","${s.threat_level}","${s.originating_ip || ''}","${s.source}"\n`;
        });
        const blob = new Blob([csv], { type: "text/csv" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `mailsentry-incident-audit-${Date.now()}.csv`;
        a.click();
    });

    // Load Metrics
    async function loadStats() {
        try {
            const resp = await fetch("/api/stats");
            const data = await resp.json();
            statTotal.textContent = data.total_scans;
            statCritical.textContent = data.critical_threats;
            statSafe.textContent = data.safe_emails;
            statRate.textContent = data.threat_interception_rate;
        } catch (e) {
            console.error("Failed to load statistics", e);
        }
    }

    // Load Incident History Table
    async function loadHistory() {
        try {
            const resp = await fetch("/api/scans");
            cachedScans = await resp.json();

            if (!cachedScans || cachedScans.length === 0) {
                historyTbody.innerHTML = `<tr><td colspan="8" class="empty-state">No incidents logged in the audit trail yet. Run an investigation above.</td></tr>`;
                return;
            }

            historyTbody.innerHTML = "";
            cachedScans.forEach(s => {
                const tr = document.createElement("tr");
                const scoreColor = s.risk_score >= 80 ? "text-danger" : (s.risk_score >= 40 ? "text-warning" : "text-success");
                const badgeClass = s.risk_score >= 80 ? "badge-danger" : (s.risk_score >= 40 ? "badge-neutral" : "badge-success");
                
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${s.created_at}</td>
                    <td><strong style="color: #F8FAFC;">${escapeHtml(s.sender_email || s.sender_domain || 'Unknown')}</strong></td>
                    <td style="color: #CBD5E1;">${escapeHtml((s.subject || 'No Subject').substring(0, 36))}</td>
                    <td><span class="badge badge-neutral">${escapeHtml(s.attack_category)}</span></td>
                    <td style="font-family: var(--font-mono); font-weight: 700;" class="${scoreColor}">${s.risk_score} / 100</td>
                    <td><span class="badge ${badgeClass}">${escapeHtml(s.threat_level)}</span></td>
                    <td style="font-family: var(--font-mono); font-size: 11px; color: #94A3B8;">${s.originating_ip || 'Internal / Direct'}</td>
                    <td><button class="btn btn-outline btn-sm btn-inspect" data-id="${s.id}">Dossier</button></td>
                `;
                historyTbody.appendChild(tr);
            });

            // Attach row click inspector
            document.querySelectorAll(".btn-inspect").forEach(btn => {
                btn.addEventListener("click", () => {
                    const scanId = parseInt(btn.getAttribute("data-id"));
                    const scan = cachedScans.find(x => x.id === scanId);
                    if (scan) openModal(scan);
                });
            });
        } catch (e) {
            historyTbody.innerHTML = `<tr><td colspan="8" class="empty-state">Error fetching incident audit logs.</td></tr>`;
        }
    }

    btnRefreshHistory.addEventListener("click", () => {
        loadStats();
        loadHistory();
    });

    // Modal Inspection
    function openModal(scan) {
        modalBody.innerHTML = `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 12px; margin-bottom: 16px;">
                <div><span style="color: var(--text-muted); display: block;">TIMESTAMP:</span> <strong>${scan.created_at}</strong></div>
                <div><span style="color: var(--text-muted); display: block;">TELEMETRY SOURCE:</span> <code>${scan.source}</code></div>
                <div><span style="color: var(--text-muted); display: block;">SENDER IDENTITY:</span> <code>${escapeHtml(scan.sender_email || 'N/A')}</code></div>
                <div><span style="color: var(--text-muted); display: block;">ORIGINATING IP:</span> <code>${scan.originating_ip || 'Internal / Proxy'}</code></div>
                <div><span style="color: var(--text-muted); display: block;">CLASSIFICATION:</span> <strong>${escapeHtml(scan.attack_category)}</strong></div>
                <div><span style="color: var(--text-muted); display: block;">SEVERITY:</span> <strong>${scan.threat_level} (${scan.risk_score}/100)</strong></div>
            </div>
            <div style="margin-bottom: 14px;">
                <span style="color: var(--text-muted); font-size: 11px; display: block; margin-bottom: 4px;">SUBJECT LINE:</span>
                <div style="background: var(--bg-input); padding: 8px 12px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px;">${escapeHtml(scan.subject || 'N/A')}</div>
            </div>
            <h4 style="font-size: 12px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Forensic Findings:</h4>
            <ul style="padding-left: 18px; font-size: 12px; color: #CBD5E1; margin-bottom: 14px;">
                ${(scan.evidence || []).map(e => `<li style="margin-bottom: 4px;">${escapeHtml(e)}</li>`).join("")}
            </ul>
            <h4 style="font-size: 12px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px;">Recommended Remediation:</h4>
            <ul style="padding-left: 18px; font-size: 12px; color: #94A3B8;">
                ${(scan.recommendations || []).map(r => `<li style="margin-bottom: 4px;">${escapeHtml(r)}</li>`).join("")}
            </ul>
        `;
        scanModal.classList.add("open");
    }

    function closeModal() {
        scanModal.classList.remove("open");
    }

    modalClose.addEventListener("click", closeModal);
    modalBackdrop.addEventListener("click", closeModal);

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Initialize
    loadStats();
    loadHistory();
});
