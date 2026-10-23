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
    const btnPrintReport = document.getElementById("btn-print-report");

    const resultsPanel = document.getElementById("results-panel");
    const resThreatLevel = document.getElementById("res-threat-level");
    const resIncidentId = document.getElementById("res-incident-id");
    const resScore = document.getElementById("res-score");
    const resCategory = document.getElementById("res-category");
    const resSender = document.getElementById("res-sender");
    const resOriginIp = document.getElementById("res-origin-ip");
    const resAuthSummary = document.getElementById("res-auth-summary");
    const resEvidenceList = document.getElementById("res-evidence-list");
    const resReasoningText = document.getElementById("res-reasoning-text");
    const resActionList = document.getElementById("res-action-list");

    const blockMitre = document.getElementById("block-mitre");
    const resMitreList = document.getElementById("res-mitre-list");
    const blockLinks = document.getElementById("block-links");
    const resLinksTbody = document.getElementById("res-links-tbody");

    const statTotal = document.getElementById("stat-total");
    const statCritical = document.getElementById("stat-critical");
    const statSafe = document.getElementById("stat-safe");
    const statRate = document.getElementById("stat-rate");
    const historyTbody = document.getElementById("history-tbody");

    const filterSearch = document.getElementById("filter-search");
    const filterPills = document.querySelectorAll(".filter-pill");

    const scanModal = document.getElementById("scan-modal");
    const modalClose = document.getElementById("modal-close");
    const modalBackdrop = document.getElementById("modal-backdrop");
    const modalBody = document.getElementById("modal-body");

    let currentReport = null;
    let cachedScans = [];
    let activeFilter = "all";

    // Realistic Samples
    const SAMPLE_PHISHING = `From: PayPal Security <security@paypa1-support.com>
To: target.user@corporate.com
Subject: URGENT: Your PayPal Account Has Been Suspended!

Dear Customer,

We detected multiple failed login attempts on your account.
Your account will be terminated in 30 minutes unless you verify your identity.

Please confirm your password immediately at:
https://paypa1-support.com/verify-identity?token=89401941

PayPal Security Team`;

    const SAMPLE_HEADERS = `Received: from mail-relay.phishingnet.ru ([185.220.101.5]) by mx.targetcorp.com; Fri, 23 Oct 2026 14:10:02 +0000
Received-SPF: fail (domain of support@micros0ft-login.xyz does not designate 185.220.101.5 as permitted sender)
Authentication-Results: dkim=fail header.d=micros0ft-login.xyz; dmarc=reject
From: Microsoft Admin <support@micros0ft-login.xyz>
To: target@targetcorp.com
Subject: Critical Security Notice: Password Expiring

Your enterprise account password expires today.
Update your credentials immediately at https://micros0ft-login.xyz/auth`;

    const SAMPLE_CLEAN = `Received: from mail-pj1.google.com ([209.85.216.50]) by mx.targetcorp.com; Fri, 23 Oct 2026 14:15:22 +0000
Received-SPF: pass (domain of notifications@calendar.google.com designates 209.85.216.50 as permitted sender)
Authentication-Results: dkim=pass header.d=google.com; dmarc=pass
From: Google Calendar <notifications@calendar.google.com>
To: user@targetcorp.com
Subject: Meeting Reminder: Sprint Review at 4:00 PM

Hi Team,

Reminder for our scheduled Sprint Architecture Review today at 4:00 PM.
Google Meet: https://meet.google.com/xyz-abcd-efg

Best,
Product Engineering`;

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

    // Keyboard Shortcut (Cmd/Ctrl + Enter)
    emailInput.addEventListener("keydown", (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
            e.preventDefault();
            runAnalysis();
        }
    });

    // Print Dossier
    btnPrintReport.addEventListener("click", () => {
        window.print();
    });

    // Run Forensic Analysis
    async function runAnalysis() {
        const text = emailInput.value.trim();
        if (!text) {
            alert("Please paste email content or RFC headers to analyze.");
            return;
        }

        btnAnalyze.disabled = true;
        btnAnalyze.textContent = "Analyzing...";

        try {
            const resp = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ raw_text: text, source: "web_console" })
            });

            if (!resp.ok) throw new Error("Analysis failed");
            const data = await resp.json();
            currentReport = data;

            // Show Results
            resultsPanel.style.display = "block";
            const incidentId = "INC-2026-" + Math.floor(1000 + Math.random() * 9000);
            resIncidentId.textContent = incidentId;

            // Score and Verdict
            const score = data.risk_score;
            resScore.textContent = score;

            if (score >= 80) {
                resThreatLevel.className = "verdict-tag";
                resThreatLevel.textContent = "CRITICAL THREAT";
            } else if (score >= 40) {
                resThreatLevel.className = "verdict-tag suspicious";
                resThreatLevel.textContent = "SUSPICIOUS";
            } else {
                resThreatLevel.className = "verdict-tag safe";
                resThreatLevel.textContent = "CLEAN BASELINE";
            }

            resCategory.textContent = data.attack_category;
            resSender.textContent = data.sender_email || "Unknown";
            resOriginIp.textContent = data.originating_ip ? `${data.originating_ip} (${data.ip_country || 'Global'})` : "Direct / Relay";

            // Auth summary
            let spfStatus = "N/A";
            let dkimStatus = "N/A";
            const evString = JSON.stringify(data.evidence || []);
            if (evString.includes("SPF Authentication FAILED")) spfStatus = "FAIL";
            else if (text.includes("Received-SPF: pass")) spfStatus = "PASS";

            if (evString.includes("DKIM Cryptographic Signature Invalid") || evString.includes("DKIM Signing Domain")) dkimStatus = "FAIL";
            else if (text.includes("dkim=pass")) dkimStatus = "PASS";

            resAuthSummary.textContent = `SPF: ${spfStatus} | DKIM: ${dkimStatus}`;

            // MITRE ATT&CK Mapping
            const mitre = data.mitre_tactics || [];
            if (mitre.length > 0) {
                blockMitre.style.display = "block";
                resMitreList.innerHTML = "";
                mitre.forEach(m => {
                    const span = document.createElement("span");
                    span.className = "mitre-chip";
                    span.textContent = m;
                    resMitreList.appendChild(span);
                });
            } else {
                blockMitre.style.display = "none";
            }

            // Link Decomposition
            const links = data.links_breakdown || [];
            if (links.length > 0) {
                blockLinks.style.display = "block";
                resLinksTbody.innerHTML = "";
                links.forEach(l => {
                    const tr = document.createElement("tr");
                    const statusClass = l.is_typosquatting ? "badge-tag danger" : "badge-tag safe";
                    tr.innerHTML = `
                        <td style="font-family: var(--font-mono); font-size: 11px; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(l.url)}</td>
                        <td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(l.host)}</td>
                        <td style="color: var(--text-white); font-weight: 500;">${l.mimicked_brand ? escapeHtml(l.mimicked_brand.toUpperCase()) : '—'}</td>
                        <td><span class="${statusClass}">${l.verdict}</span></td>
                    `;
                    resLinksTbody.appendChild(tr);
                });
            } else {
                blockLinks.style.display = "none";
            }

            // Evidence List
            resEvidenceList.innerHTML = "";
            (data.evidence || []).forEach(item => {
                const li = document.createElement("li");
                li.innerHTML = item.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
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

            // Scroll to results
            resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });

            // Refresh logs
            loadStats();
            loadHistory();
        } catch (err) {
            alert("Error during investigation: " + err.message);
        } finally {
            btnAnalyze.disabled = false;
            btnAnalyze.textContent = "Analyze Message";
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

    // Filtering & Search
    function renderFilteredHistory() {
        const query = (filterSearch.value || "").toLowerCase().trim();

        let filtered = cachedScans.filter(s => {
            // Severity filter
            if (activeFilter === "critical" && s.risk_score < 80) return false;
            if (activeFilter === "suspicious" && (s.risk_score < 40 || s.risk_score >= 80)) return false;
            if (activeFilter === "safe" && s.risk_score >= 40) return false;

            // Search query
            if (query) {
                const combined = `${s.sender_email || ''} ${s.sender_domain || ''} ${s.subject || ''} ${s.attack_category || ''}`.toLowerCase();
                if (!combined.includes(query)) return false;
            }
            return true;
        });

        if (filtered.length === 0) {
            historyTbody.innerHTML = `<tr><td colspan="8" class="table-empty">No incidents match the search criteria.</td></tr>`;
            return;
        }

        historyTbody.innerHTML = "";
        filtered.forEach(s => {
            const tr = document.createElement("tr");
            const tagClass = s.risk_score >= 80 ? "badge-tag danger" : (s.risk_score >= 40 ? "badge-tag" : "badge-tag safe");
            
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); font-size: 11px;">${s.created_at}</td>
                <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-white);">${escapeHtml(s.sender_email || s.sender_domain || 'Unknown')}</td>
                <td>${escapeHtml((s.subject || 'No Subject').substring(0, 36))}</td>
                <td><span class="badge-tag">${escapeHtml(s.attack_category)}</span></td>
                <td style="font-family: var(--font-mono); font-weight: 600;">${s.risk_score}/100</td>
                <td><span class="${tagClass}">${escapeHtml(s.threat_level)}</span></td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${s.originating_ip || 'Internal'}</td>
                <td><button class="btn btn-secondary btn-sm btn-inspect" data-id="${s.id}">View</button></td>
            `;
            historyTbody.appendChild(tr);
        });

        // Re-attach modal listeners
        document.querySelectorAll(".btn-inspect").forEach(btn => {
            btn.addEventListener("click", () => {
                const scanId = parseInt(btn.getAttribute("data-id"));
                const scan = cachedScans.find(x => x.id === scanId);
                if (scan) openModal(scan);
            });
        });
    }

    filterSearch.addEventListener("input", renderFilteredHistory);

    filterPills.forEach(pill => {
        pill.addEventListener("click", () => {
            filterPills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            activeFilter = pill.getAttribute("data-filter");
            renderFilteredHistory();
        });
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
            renderFilteredHistory();
        } catch (e) {
            historyTbody.innerHTML = `<tr><td colspan="8" class="table-empty">Error fetching records.</td></tr>`;
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
                <div><span style="color: var(--text-muted); display: block; font-size: 11px;">TIME:</span> <strong>${scan.created_at}</strong></div>
                <div><span style="color: var(--text-muted); display: block; font-size: 11px;">SOURCE:</span> <code>${scan.source}</code></div>
                <div><span style="color: var(--text-muted); display: block; font-size: 11px;">SENDER:</span> <code>${escapeHtml(scan.sender_email || 'N/A')}</code></div>
                <div><span style="color: var(--text-muted); display: block; font-size: 11px;">ORIGIN IP:</span> <code>${scan.originating_ip || 'Internal'}</code></div>
                <div><span style="color: var(--text-muted); display: block; font-size: 11px;">CATEGORY:</span> <strong>${escapeHtml(scan.attack_category)}</strong></div>
                <div><span style="color: var(--text-muted); display: block; font-size: 11px;">SCORE:</span> <strong>${scan.risk_score} / 100 (${scan.threat_level})</strong></div>
            </div>
            <div style="margin-bottom: 14px;">
                <span style="color: var(--text-muted); font-size: 11px; display: block; margin-bottom: 4px;">SUBJECT:</span>
                <div style="background: var(--bg-black); border: 1px solid var(--border-subtle); padding: 8px 12px; border-radius: 4px; font-family: var(--font-mono); font-size: 12px;">${escapeHtml(scan.subject || 'N/A')}</div>
            </div>
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 6px;">Evidence Chain:</div>
            <ul style="padding-left: 18px; font-size: 12px; color: var(--text-secondary); margin-bottom: 14px;">
                ${(scan.evidence || []).map(e => `<li style="margin-bottom: 4px;">${escapeHtml(e)}</li>`).join("")}
            </ul>
            <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 6px;">Remediation Actions:</div>
            <ul style="padding-left: 18px; font-size: 12px; color: var(--text-muted);">
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
