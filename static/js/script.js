
lucide.createIcons();

let currentReport = null;

const themeBtn = document.getElementById('themeToggle');
let isDark = false;
themeBtn.addEventListener('click', () => {
    isDark = !isDark;
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
});

async function startScan() {
    const fileInput = document.getElementById('fileInput');
    if (!fileInput.files[0]) return alert("Please select an APK file.");

    document.getElementById('loader').classList.remove('hidden');
    hideAllCards();

    // Hide export button and clear old data
    document.getElementById('exportBtn').classList.add('hidden');
    currentReport = null;

    document.getElementById('scanBtn').disabled = true;
    document.getElementById('scanBtn').innerHTML = '<i data-lucide="loader"></i> Uploading...';
    lucide.createIcons();

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
        // Step 1: Submit the scan
        const response = await fetch('/scan', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();

        if (!data.success) {
            alert("Error: " + data.error);
            resetUI();
            return;
        }

        // Step 2: Poll for status
        const jobId = data.job_id;
        document.getElementById('scanBtn').innerHTML = '<i data-lucide="loader"></i> Analyzing...';
        lucide.createIcons();

        pollStatus(jobId);

    } catch (err) {
        alert("Upload failed: " + err);
        resetUI();
    }
}

async function pollStatus(jobId) {
    const maxAttempts = 180; // 3 minutes max (180 * 1 second)
    let attempts = 0;

    const poll = async () => {
        try {
            const response = await fetch(`/status/${jobId}`);
            const data = await response.json();

            if (data.status === 'completed' && data.success) {
                // Analysis complete
                renderReport(data.report);
                resetUI();
            } else if (data.status === 'failed') {
                // Analysis failed
                alert("Analysis failed: " + (data.error || 'Unknown error'));
                resetUI();
            } else {
                // Still processing
                attempts++;
                if (attempts >= maxAttempts) {
                    alert("Analysis timed out after 3 minutes");
                    resetUI();
                } else {
                    // Poll again in 1 second
                    setTimeout(poll, 1000);
                }
            }
        } catch (err) {
            alert("Status check failed: " + err);
            resetUI();
        }
    };

    poll();
}

function hideAllCards() {
    const cards = ['metaCard', 'findingsCard', 'permissionsCard', 'componentsCard',
        'apisCard', 'secretsCard', 'nativeCard', 'nestedCard', 'yaraCard'];
    cards.forEach(id => {
        const card = document.getElementById(id);
        if (card) card.classList.add('hidden');
    });
}

function resetUI() {
    document.getElementById('loader').classList.add('hidden');
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('scanBtn').innerHTML = '<i data-lucide="search"></i> Start Analysis';
    lucide.createIcons();
}
function renderReport(report) {
    // Save report data and show export button
    currentReport = report;
    document.getElementById('exportBtn').classList.remove('hidden');

    // Show all cards
    document.getElementById('scoreCard').style.opacity = "1";
    document.getElementById('metaCard').classList.remove('hidden');
    document.getElementById('findingsCard').classList.remove('hidden');
    document.getElementById('permissionsCard').classList.remove('hidden');
    document.getElementById('componentsCard').classList.remove('hidden');
    document.getElementById('apisCard').classList.remove('hidden');
    document.getElementById('secretsCard').classList.remove('hidden');
    document.getElementById('nativeCard').classList.remove('hidden');
    document.getElementById('nestedCard').classList.remove('hidden');
    document.getElementById('yaraCard').classList.remove('hidden');

    // 1. Risk Score
    const score = report.risk_score;
    const level = report.risk_level;
    document.getElementById('riskDisplay').innerHTML = `
        <div class="risk-badge risk-${level}" style="font-size: 1.5rem; margin-bottom: 10px;">
            ${level} RISK
        </div>
        <p>Score: <strong>${score}</strong> / 100</p>
    `;

    // 2. File Info
    document.getElementById('fileInfoDisplay').innerHTML = `
        <p><strong>Package:</strong> ${report.package_name || 'Unknown'}</p>
        <p><strong>Name:</strong> ${report.app_name || 'Unknown'}</p>
        <p><strong>MD5:</strong> <span style="font-family: monospace; font-size: 0.85rem; word-break: break-all;">${report.file_info.md5}</span></p>
        <p><strong>SHA256:</strong> <span style="font-family: monospace; font-size: 0.85rem; word-break: break-all;">${report.file_info.sha256}</span></p>
        <p><strong>Size:</strong> ${(report.file_info.size / 1024 / 1024).toFixed(2)} MB</p>
        <p><strong>Entropy:</strong> ${report.file_info.entropy.toFixed(4)}</p>
        <p><strong>Signer:</strong> ${report.file_info.signer || 'Unsigned'}</p>
    `;

    // 3. Meta Info
    if (report.meta) {
        document.getElementById('metaInfo').innerHTML = `
            <p><strong>Filename:</strong> ${report.meta.filename}</p>
            <p><strong>Timestamp:</strong> ${report.meta.timestamp}</p>
            <p><strong>Tool:</strong> ${report.meta.tool}</p>
        `;
    }

    // 4. Findings
    const findingsList = document.getElementById('findingsList');
    if (report.findings && report.findings.length > 0) {
        findingsList.innerHTML = report.findings.map(f => `<li style="margin-bottom: 8px;">🔴 ${f}</li>`).join('');
    } else {
        findingsList.innerHTML = '<li class="muted">No critical findings.</li>';
    }

    // 5. Permissions
    const permsList = document.getElementById('permsList');
    if (report.permissions && report.permissions.length > 0) {
        permsList.innerHTML = report.permissions.map(p =>
            `<span class="permission-badge">${p.replace('android.permission.', '')}</span>`
        ).join('');
    } else {
        permsList.innerHTML = "<span class='muted'>No permissions found.</span>";
    }

    // 6. Components
    if (report.components) {
        const activitiesList = document.getElementById('activitiesList');
        activitiesList.innerHTML = report.components.activities && report.components.activities.length > 0
            ? report.components.activities.map(a => `<li style="margin-bottom: 5px; font-size: 0.85rem;">📱 ${a}</li>`).join('')
            : '<li class="muted">None</li>';

        const servicesList = document.getElementById('servicesList');
        servicesList.innerHTML = report.components.services && report.components.services.length > 0
            ? report.components.services.map(s => `<li style="margin-bottom: 5px; font-size: 0.85rem;">⚙️ ${s}</li>`).join('')
            : '<li class="muted">None</li>';

        const receiversList = document.getElementById('receiversList');
        receiversList.innerHTML = report.components.receivers && report.components.receivers.length > 0
            ? report.components.receivers.map(r => `<li style="margin-bottom: 5px; font-size: 0.85rem;">📡 ${r}</li>`).join('')
            : '<li class="muted">None</li>';
    }

    // 7. Dangerous APIs
    const apisList = document.getElementById('apisList');
    if (report.dangerous_apis && Object.keys(report.dangerous_apis).length > 0) {
        let apisHTML = '';
        for (const [category, methods] of Object.entries(report.dangerous_apis)) {
            apisHTML += `<h3 style="margin-top: 10px;">${category}</h3><ul style="list-style: none;">`;
            methods.forEach(m => {
                apisHTML += `<li style="margin-bottom: 5px; font-size: 0.85rem;">⚠️ ${m}</li>`;
            });
            apisHTML += '</ul>';
        }
        apisList.innerHTML = apisHTML;
    } else {
        apisList.innerHTML = '<p class="muted">No dangerous APIs detected.</p>';
    }

    // 8. Secrets
    const secretsList = document.getElementById('secretsList');
    if (report.secrets && Object.keys(report.secrets).length > 0) {
        let secretsText = "";
        for (const [key, vals] of Object.entries(report.secrets)) {
            if (vals && vals.length > 0) {
                secretsText += `[${key}]\n${vals.join('\n')}\n\n`;
            }
        }
        secretsList.textContent = secretsText || "No secrets found.";
    } else {
        secretsList.textContent = "No secrets found.";
    }

    // 9. Native Libraries
    const nativeLibsList = document.getElementById('nativeLibsList');
    if (report.native_libs && report.native_libs.length > 0) {
        nativeLibsList.innerHTML = report.native_libs.map(lib =>
            `<li style="margin-bottom: 5px; font-size: 0.85rem;">📚 ${lib}</li>`
        ).join('');
    } else {
        nativeLibsList.innerHTML = '<li class="muted">No native libraries found.</li>';
    }

    // 10. Nested APKs
    const nestedList = document.getElementById('nestedList');
    if (report.nested_apks && report.nested_apks.length > 0) {
        nestedList.innerHTML = report.nested_apks.map(apk =>
            `<li style="margin-bottom: 5px; font-size: 0.85rem; color: var(--md-sys-color-error);">📦 ${apk}</li>`
        ).join('');
    } else {
        nestedList.innerHTML = '<li class="muted">No nested APKs found.</li>';
    }

    // 11. YARA Matches
    const yaraList = document.getElementById('yaraList');
    if (report.yara_matches && report.yara_matches.length > 0) {
        yaraList.innerHTML = report.yara_matches.map(match =>
            `<li style="margin-bottom: 8px;">🛡️ ${match}</li>`
        ).join('');
    } else {
        yaraList.innerHTML = '<li class="muted">No YARA matches.</li>';
    }

    lucide.createIcons();
}

function exportReport() {
    if (!currentReport) return;

    const dataStr = JSON.stringify(currentReport, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `report_${currentReport.package_name || 'analysis'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
