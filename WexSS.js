// ================================================
// WexSS - WexScan Ultra Professional Privacy Analyzer
// v2.3 - Correção de Escape + Código Limpo
// GitHub: WexScan
// ================================================

const CONFIG = {
    version: "2.3",
    appName: "WexSS"
};

// ====================== EXTRAÇÃO DE DADOS ======================
function extract_domains(lines) {
    const domains = new Set();
    const appsMap = new Map();

    lines.forEach(line => {
        if (!line.trim()) return;
        try {
            const entry = JSON.parse(line);
            const appName = entry.bundleIdentifier || entry.accessor?.identifier || "Unknown App";

            if (!appsMap.has(appName)) {
                appsMap.set(appName, { domains: new Set(), permissions: new Set(), count: 0 });
            }
            const app = appsMap.get(appName);
            app.count++;

            if (entry.domain) {
                const d = entry.domain.toLowerCase().trim();
                domains.add(d);
                app.domains.add(d);
            }
            if (entry.url) {
                try {
                    const host = new URL(entry.url).hostname.toLowerCase();
                    domains.add(host);
                    app.domains.add(host);
                } catch(e) {}
            }
            if (entry.tccService || entry.permission) {
                app.permissions.add(entry.tccService || entry.permission);
            }
        } catch(e) {}
    });

    return {
        allDomains: Array.from(domains),
        apps: Array.from(appsMap.entries()).map(([name, data]) => ({
            appName: name,
            domainsCount: data.domains.size,
            permissions: Array.from(data.permissions),
            accessCount: data.count
        }))
    };
}

function extract_timestamps(lines) {
    const timestamps = [];
    lines.forEach(line => {
        try {
            const entry = JSON.parse(line);
            if (entry.timestamp) timestamps.push(entry.timestamp);
        } catch(e) {}
    });
    return timestamps;
}

function sanitize_inputs(data) {
    return data.filter(line => line && typeof line === "string" && line.trim().length > 5);
}

function validate_input_data(lines) {
    return lines.length > 5;
}

// ====================== ANÁLISE DE RISCO ======================
function classify_risk_level(data) {
    let score = 0;
    if (data.trackersCount > 15) score += 40;
    else if (data.trackersCount > 8) score += 25;

    data.riskyApps.forEach(app => {
        if (app.domainsCount > 15) score += 20;
        if (app.permissions.some(p => /location|camera|microphone|contacts/i.test(p))) score += 15;
    });

    const riskLevel = score >= 70 ? "CRITICAL" : score >= 45 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";
    return { riskScore: Math.min(score, 100), riskLevel };
}

function is_critical_risk(data) { return data.riskLevel === "CRITICAL"; }
function is_high_risk(data) { return data.riskLevel === "HIGH"; }
function is_medium_risk(data) { return data.riskLevel === "MEDIUM"; }
function is_low_risk(data) { return data.riskLevel === "LOW"; }

function detect_anomalies(apps) {
    return apps.filter(app => 
        app.domainsCount > 20 || 
        (app.permissions.some(p => /location/i.test(p)) && app.accessCount > 40)
    ).map(app => app.appName + " (" + app.domainsCount + " domínios)");
}

function generate_recommendation(analysis) {
    if (analysis.riskLevel === "CRITICAL") 
        return "Recomendação urgente: Revise permissões de apps com muitos trackers e acesso a localização/câmera/microfone.";
    if (analysis.riskLevel === "HIGH") 
        return "Atenção: Considere limitar permissões de apps suspeitos.";
    return "Nível de privacidade aceitável. Continue monitorando trackers periodicamente.";
}

// ====================== RELATÓRIOS E MÉTRICAS ======================
function generate_json_report(results) {
    const fm = FileManager.local();
    const dir = fm.joinPath(fm.documentsDirectory(), "WexSS_Reports");
    fm.createDirectory(dir, true);
    const ts = new Date().toISOString().slice(0,19).replace(/[:.]/g, "-");
    fm.writeString(fm.joinPath(dir, "WexSS_Full_Report_" + ts + ".json"), JSON.stringify(results, null, 2));
}

function generate_markdown_report(analysis) {
    const fm = FileManager.local();
    const dir = fm.joinPath(fm.documentsDirectory(), "WexSS_Reports");
    fm.createDirectory(dir, true);
    const ts = new Date().toISOString().slice(0,19).replace(/[:.]/g, "-");

    let md = "# WexSS - Relatório Ultra Profissional v" + CONFIG.version + "\n\n";
    md += "**Data:** " + new Date().toLocaleString('pt-BR') + "\n";
    md += "**Risco Geral:** " + analysis.riskLevel + " (Score: " + analysis.riskScore + ")\n\n";
    md += "**Domínios únicos:** " + analysis.totalDomains + "\n";
    md += "**Trackers detectados:** " + analysis.trackersCount + "\n\n";

    md += "## Apps de Alto Risco\n";
    analysis.riskyApps.forEach(app => {
        md += "- **" + app.appName + "** → " + app.riskLevel + " (" + app.domainsCount + " domínios)\n";
    });

    if (analysis.anomalies && analysis.anomalies.length > 0) {
        md += "\n## Anomalias Detectadas\n";
        analysis.anomalies.forEach(a => md += "- " + a + "\n");
    }

    md += "\n**Recomendação:** " + analysis.recommendation;

    fm.writeString(fm.joinPath(dir, "WexSS_Summary_" + ts + ".md"), md);
}

// ====================== DASHBOARD ======================
function showProfessionalDashboard(analysis) {
    const html = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WexSS Dashboard v${CONFIG.version}</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0a0a0a; color: #eee; margin: 0; padding: 20px; }
        .card { background: #1f1f1f; border-radius: 18px; padding: 20px; margin: 15px 0; }
        .risk-critical { border-top: 6px solid #ff3b5c; }
        .risk-high { border-top: 6px solid #ff9500; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 14px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #2a2a2a; }
    </style>
</head>
<body>
    <h1 style="text-align:center;color:#00ff9d;">WexSS Dashboard v${CONFIG.version}</h1>
    
    <div class="card risk-${analysis.riskLevel.toLowerCase()}">
        <h2>Risco Geral: ${analysis.riskLevel} <span style="color:#ff3b5c;">(Score ${analysis.riskScore})</span></h2>
        <p>Trackers: ${analysis.trackersCount} | Domínios: ${analysis.totalDomains}</p>
    </div>

    <div class="card">
        <h3>Apps de Alto Risco</h3>
        <table>
            <tr><th>App</th><th>Domínios</th><th>Risco</th></tr>
            ${analysis.riskyApps.map(app => `
                <tr>
                    <td>${app.appName}</td>
                    <td>${app.domainsCount}</td>
                    <td>${app.riskLevel}</td>
                </tr>
            `).join('')}
        </table>
    </div>

    ${analysis.anomalies && analysis.anomalies.length ? `
    <div class="card">
        <h3>Anomalias Detectadas</h3>
        <ul>\( {analysis.anomalies.map(a => `<li> \){a}</li>`).join('')}</ul>
    </div>` : ''}

    <div class="card">
        <h3>Recomendação</h3>
        <p>${analysis.recommendation}</p>
    </div>
</body>
</html>`;

    const webview = new WebView();
    webview.loadHTML(html);
    webview.present();
}

// ====================== EXECUÇÃO PRINCIPAL ======================
async function run_full_scan() {
    console.log(`🚀 Iniciando WexSS v${CONFIG.version}`);

    let filePath;
    try {
        filePath = await DocumentPicker.openFile();
    } catch (e) {
        let a = new Alert();
        a.title = "Seleção cancelada";
        a.message = "Nenhum arquivo foi selecionado.";
        a.addAction("OK");
        await a.present();
        return;
    }

    const fm = FileManager.local();
    let content = fm.readString(filePath);
    let lines = sanitize_inputs(content.split("\n"));

    if (!validate_input_data(lines)) {
        let a = new Alert();
        a.title = "Arquivo inválido";
        a.message = "O arquivo selecionado não parece ser um relatório de privacidade válido.";
        a.addAction("OK");
        await a.present();
        return;
    }

    const rawData = extract_domains(lines);

    const trackersCount = rawData.allDomains.filter(d => 
        ["doubleclick","google-analytics","facebook","appsflyer","adjust","criteo"].some(t => d.includes(t))
    ).length;

    const riskyApps = rawData.apps
        .filter(app => app.domainsCount > 10)
        .map(app => ({
            appName: app.appName,
            domainsCount: app.domainsCount,
            riskLevel: app.domainsCount > 15 ? "CRITICAL" : "HIGH"
        }));

    const anomalies = detect_anomalies(rawData.apps);

    let analysis = {
        totalDomains: rawData.allDomains.length,
        trackersCount: trackersCount,
        riskyApps: riskyApps,
        anomalies: anomalies,
        riskScore: 0,
        riskLevel: "LOW",
        recommendation: ""
    };

    const riskInfo = classify_risk_level(analysis);
    analysis.riskScore = riskInfo.riskScore;
    analysis.riskLevel = riskInfo.riskLevel;
    analysis.recommendation = generate_recommendation(analysis);

    generate_json_report(analysis);
    generate_markdown_report(analysis);
    showProfessionalDashboard(analysis);

    console.log("✅ Análise concluída com sucesso.");
}

run_full_scan().catch(err => {
    console.error("Erro:", err);
    let a = new Alert();
    a.title = "Erro no WexSS";
    a.message = err.message || "Erro inesperado.";
    a.addAction("OK");
    a.present();
});
