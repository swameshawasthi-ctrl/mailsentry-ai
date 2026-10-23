document.addEventListener("DOMContentLoaded", () => {
    // Elements
    const emailInput = document.getElementById("email-input");
    const btnAnalyze = document.getElementById("btn-analyze");
    const btnClear = document.getElementById("btn-clear");
    const btnLoadPhish = document.getElementById("btn-load-phish");
    const btnLoadClean = document.getElementById("btn-load-clean");
    const btnLoadHeaders = document.getElementById("btn-load-headers");
    const btnRefreshHistory = document.getElementById("btn-refresh-history");
    const btnExportReport = document.getElementById("btn-export-report");

    const resultsPanel = document.getElementById("results-panel");
    const resScore = document.getElementById("res-score");
    const resThreatLevel = document.getElementById("res-threat-level");
    const resCategory = document.getElementById("res-category");
    const resSender = document.getElementById("res-sender");
    const resEvidenceList = document.getElementById("res-evidence-list");
    const resReasoningText = document.getElementById("res-reasoning-text");
    const resActionList = document.getElementById("res-action-list");
    const gaugeProgress = document.getElementById("gauge-progress");

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

    // Sample Data
    const SAMPLE_PHISHING = `From: Security Alert <security@paypa1-support.com>
To: target.user@corporate.com
Subject: URGENT: Your PayPal Account Has Been Suspended!

Dear Customer,

We detected unauthorized logins from an unrecognized device in Russia.
Your account will be permanently deactivated within 30 minutes unless you verify your identity.

Please confirm your login password and billing info immediately at:
https://paypa1-support.com/verify-identity?token=892341

Failure to comply will result in permanent loss of access.

Sincerely,
PayPal Security Operations`;

    const SAMPLE_CLEAN = `From: Google Calendar <notifications@calendar.google.com>
To: engineering@company.com
Subject: Meeting Reminder: Architecture Review at 4:00 PM

Hi Team,

This is a scheduled reminder for our Architecture Review meeting today at 4:00 PM IST.
Join Google Meet:
https://meet.google.com/xyz-abcd-efg

Best regards,
Developer Tools Team`;

    const SAMPLE_HEADERS = `Received: from mail-relay.phishingnet.ru ([185.220.101.5]) by mx.corporate.com; Fri, 23 Oct 2026 14:02:11 +0000
Received-SPF: fail (corporate.com: domain of support@micros0ft-login.xyz does not designate 185.220.101.5 as permitted sender)
Authentication-Results: dkim=fail header.d=micros0ft-login.xyz; dmarc=reject
From: Microsoft IT Support <support@micros0ft-login.xyz>
To: admin@company.com
Subject: CRITICAL: Immediate Password Expiration Alert

Your 365 Enterprise account password expires in 15 minutes.
Reset your password immediately to prevent mailbox lockout:
https://micros0ft-login.xyz/portal/auth`;

    // Sample Loader Listeners
    btnLoadPhish.addEventListener("click", () => {
        emailInput.value = SAMPLE_PHISHING;
        emailInput.focus();
    });

    btnLoadClean.addEventListener("click", () => {
        emailInput.value = SAMPLE_CLEAN;
        emailInput.focus();
    });

    btnLoadHeaders.addEventListener("click", () => {
        emailInput.value = SAMPLE_HEADERS;
        emailInput.focus();
    });

    btnClear.addEventListener("click", () => {
        emailInput.value = "";
        resultsPanel.style.display = "none";
        emailInput.focus();
    });

    // Animate Radial Gauge
    function updateGauge(score) {
        const circumference = 314; // 2 * PI * 50
        const offset = circumference - (score / 100) * circumference;
        gaugeProgress.style.strokeDashoffset = offset;

        if (score >= 80) {
            gaugeProgress.style.stroke = "var(--danger-red)";
            resThreatLevel.className = "threat-pill";
        } else if (score >= 40) {
            gaugeProgress.style.stroke = "var(--warning-amber)";
            resThreatLevel.className = "threat-pill suspicious";
        } else {
            gaugeProgress.style.stroke = "var(--success-green)";
            resThreatLevel.className = "threat-pill safe";
        }
    }

    // Run Analysis
    async function runAnalysis() {
        const text = emailInput.value.trim();
        if (!text) {
            alert("Please paste email text or headers to analyze.");
            return;
        }

        btnAnalyze.disabled = true;
        btnAnalyze.innerHTML = `<span class="btn-icon">⏳</span> Analyzing via AI Agent...`;

        try {
            const resp = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ raw_text: text, source: "web_dashboard" })
            });

            if (!resp.ok) throw new Error("Analysis failed");
            const data = await resp.json();
            currentReport = data;

            // Render Results
            resultsPanel.style.display = "block";
            resScore.textContent = data.risk_score;
            resThreatLevel.textContent = data.threat_level;
            resCategory.textContent = data.attack_category;
            resSender.textContent = `Sender: ${data.sender_email || 'Unspecified'}`;

            updateGauge(data.risk_score);

            // Populate Evidence
            resEvidenceList.innerHTML = "";
            (data.evidence || []).forEach(item => {
                const li = document.createElement("li");
                li.innerHTML = item.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
                if (data.risk_score < 30) li.classList.add("clean");
                resEvidenceList.appendChild(li);
            });

            // Populate Reasoning
            resReasoningText.textContent = data.analyst_reasoning || "Forensic rule evaluation complete.";

            // Populate Actions
            resActionList.innerHTML = "";
            (data.recommendations || []).forEach(item => {
                const li = document.createElement("li");
                li.textContent = item.replace(/^[•\s\*\-]+/, "");
                resActionList.appendChild(li);
            });

            // Scroll to results
            resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });

            // Refresh stats & logs
            loadStats();
            loadHistory();
        } catch (err) {
            alert("Error during investigation: " + err.message);
        } finally {
            btnAnalyze.disabled = false;
            btnAnalyze.innerHTML = `<span class="btn-icon">⚡</span> Run Multi-Tool Forensics`;
        }
    }

    btnAnalyze.addEventListener("click", runAnalysis);

    // Export JSON Report
    btnExportReport.addEventListener("click", () => {
        if (!currentReport) return;
        const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `mailsentry-forensic-report-${Date.now()}.json`;
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
            console.error("Stats load failed", e);
        }
    }

    // Load Recent History Table
    async function loadHistory() {
        try {
            const resp = await fetch("/api/scans");
            const scans = await resp.json();

            if (!scans || scans.length === 0) {
                historyTbody.innerHTML = `<tr><td colspan="7" class="loading-state">No investigations recorded yet. Run your first scan above!</td></tr>`;
                return;
            }

            historyTbody.innerHTML = "";
            scans.forEach(s => {
                const tr = document.createElement("tr");
                const pillClass = s.risk_score >= 80 ? "text-danger" : (s.risk_score >= 40 ? "text-accent" : "text-success");
                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); font-size: 0.78rem;">${s.created_at}</td>
                    <td><strong>${escapeHtml(s.sender_email || s.sender_domain || 'Unknown')}</strong>${s.ip_country ? `<br><small class="text-secondary">${s.ip_country}</small>` : ''}</td>
                    <td>${escapeHtml((s.subject || 'No Subject').substring(0, 35))}</td>
                    <td><span class="chip">${escapeHtml(s.attack_category)}</span></td>
                    <td style="font-family: var(--font-mono); font-weight: bold;" class="${pillClass}">${s.risk_score} / 100</td>
                    <td><strong>${escapeHtml(s.threat_level)}</strong></td>
                    <td><button class="btn btn-secondary btn-sm btn-inspect" data-id="${s.id}">Inspect</button></td>
                `;
                historyTbody.appendChild(tr);
            });

            // Attach inspect modal listeners
            document.querySelectorAll(".btn-inspect").forEach(btn => {
                btn.addEventListener("click", () => {
                    const scanId = parseInt(btn.getAttribute("data-id"));
                    const scan = scans.find(x => x.id === scanId);
                    if (scan) openModal(scan);
                });
            });
        } catch (e) {
            historyTbody.innerHTML = `<tr><td colspan="7" class="loading-state">Error loading history logs.</td></tr>`;
        }
    }

    btnRefreshHistory.addEventListener("click", () => {
        loadStats();
        loadHistory();
    });

    // Modal Helpers
    function openModal(scan) {
        modalBody.innerHTML = `
            <div style="margin-bottom: 16px;">
                <p><strong>Timestamp:</strong> ${scan.created_at} &bull; <strong>Source:</strong> ${scan.source}</p>
                <p><strong>Sender:</strong> <code>${escapeHtml(scan.sender_email || 'N/A')}</code></p>
                <p><strong>Subject:</strong> ${escapeHtml(scan.subject || 'N/A')}</p>
                <p><strong>Threat Level:</strong> ${scan.threat_level} (${scan.risk_score}/100)</p>
                ${scan.originating_ip ? `<p><strong>Origin IP:</strong> ${scan.originating_ip} (${scan.ip_country || 'N/A'})</p>` : ''}
            </div>
            <hr style="border: 0; border-top: 1px solid var(--border-color); margin: 14px 0;">
            <h4 style="margin-bottom: 8px;">Forensic Evidence:</h4>
            <ul style="padding-left: 20px; font-size: 0.85rem; margin-bottom: 16px;">
                ${(scan.evidence || []).map(e => `<li>${escapeHtml(e)}</li>`).join("")}
            </ul>
            <h4 style="margin-bottom: 8px;">Actionable Advice:</h4>
            <ul style="padding-left: 20px; font-size: 0.85rem;">
                ${(scan.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join("")}
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

    // Initial Load
    loadStats();
    loadHistory();
});
