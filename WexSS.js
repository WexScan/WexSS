// ================================================
// WexSS - Scanner 
// ================================================

const CONFIG = {
    version: "1.3",
    reportFileName: "privacy-report.ndjson",
    highRiskKeywords: ["track", "analytics", "pixel", "beacon", "ads", "log", "collect", "doubleclick", "google-analytics", "facebook", "appsflyer", "adjust", "criteo"],
    knownTrackers: [
        "doubleclick.net", "google-analytics.com", "googletagmanager.com", "facebook.com", "fbcdn.net",
        "analytics.google.com", "adobedtm.com", "scorecardresearch.com", "appsflyer.com", "adjust.com",
        "branch.io", "app-measurement.com", "criteo.com", "demdex.net"
    ]
};

// ====================== FUNÇÕES DE EXTRAÇÃO ======================
function extractDomainsFromReport(lines) {
    const domains = new Set();
    const appsData = new Map();

    lines.forEach(line => {
        if (!line.trim()) return;
        try {
            const entry = JSON.parse(line);
            const appName = entry.bundleIdentifier || entry.accessor?.identifier || "Unknown";

            if (!appsData.has(appName)) {
                appsData.set(appName, { domains: new Set(), permissions: new Set(), count: 0, timestamps: [] });
            }
            const app = appsData.get(appName);
            app.count++;

            if (entry.domain) {
                const d = entry.domain.toLowerCase().trim();
                domains.add(d);
                app.domains.add(d);
            }
            if (entry.url) {
                try {
                    const hostname = new URL(entry.url).hostname.toLowerCase();
                    domains.add(hostname);
                    app.domains.add(hostname);
                } catch(e) {}
            }
            if (entry.tccService || entry.permission) {
                app.permissions.add(entry.tccService || entry.permission);
            }
            if (entry.timestamp) app.timestamps.push(entry.timestamp);
        } catch(e) {}
    });

    return {
        allDomains: Array.from(domains),
        apps: Array.from(appsData.entries()).map(([name, data]) => ({
            appName: name,
            domains: Array.from(data.domains),
            permissions: Array.from(data.permissions),
            accessCount: data.count,
            timestamps: data.timestamps
        }))
    };
}

// ====================== ANÁLISE DE SEGURANÇA / RISCO ======================
function classifyRiskLevel(analysis) {
    let riskScore = 0;
    const tags = [];

    if (analysis.trackersFound.length > 15) { riskScore += 40; tags.push("Muitos trackers"); }
    if (analysis.trackersFound.length > 8)  { riskScore += 25; tags.push("Trackers moderados"); }

    analysis.riskyApps.forEach(app => {
        if (app.domainsCount > 15) riskScore += 20;
        if (app.permissions.some(p => /location|camera|microphone|contacts|photo/i.test(p))) riskScore += 15;
    });

    let riskLevel = "LOW";
    if (riskScore >= 70) riskLevel = "CRITICAL";
    else if (riskScore >= 45) riskLevel = "HIGH";
    else if (riskScore >= 20) riskLevel = "MEDIUM";

    return { riskScore: Math.min(riskScore, 100), riskLevel, tags };
}

// ====================== DETECÇÃO DE ANOMALIAS ======================
function detectAnomalies(apps) {
    const anomalies = [];
    apps.forEach(app => {
        if (app.domains.length > 20) {
            anomalies.push(`${app.appName} acessou ${app.domains.length} domínios (suspeito)`);
        }
        if (app.permissions.some(p => /location/i.test(p)) && app.accessCount > 50) {
            anomalies.push(`${app.appName} acessou localização muitas vezes`);
        }
    });
    return anomalies;
}

// ====================== GERAÇÃO DE RELATÓRIOS ======================
async function generateReports(analysis, rawData) {
    const fm = FileManager.local();
    const reportsDir = fm.joinPath(fm.documentsDirectory(), "WexSS_Reports");
    fm.createDirectory(reportsDir, true);

    const timestamp = new Date().toISOString().slice(0,19).replace(/[:.]/g, "-");

    // JSON Completo
    const fullReport = {
        scanDate: new Date().toISOString(),
        summary: analysis,
        rawApps: rawData.apps.slice(0, 50)
    };
    fm.writeString(fm.joinPath(reportsDir, `WexSS_Full_${timestamp}.json`), JSON.stringify(fullReport, null, 2));

    // Markdown Resumo
    let md = `# WexSS - Relatório de Privacidade iOS v${CONFIG.version}\n\n`;
    md += `**Data:** ${new Date().toLocaleString('pt-BR')}\n`;
    md += `**Risco Geral:** ${analysis.riskLevel} (Score: ${analysis.riskScore})\n\n`;
    md += `**Domínios únicos:** ${analysis.totalUniqueDomains}\n`;
    md += `**Trackers detectados:** ${analysis.trackersFound.length}\n`;
    md += `**Apps de alto risco:** ${analysis.riskyApps.length}\n\n`;

    md += `## Apps de Alto Risco\n`;
    analysis.riskyApps.forEach(app => {
        md += `- **${app.appName}** → \( {app.riskLevel} ( \){app.domainsCount} domínios)\n`;
    });

    md += `\n## Trackers Encontrados\n`;
    analysis.trackersFound.forEach(t => md += `- ${t}\n`);

    if (analysis.anomalies && analysis.anomalies.length > 0) {
        md += `\n## Anomalias Detectadas\n`;
        analysis.anomalies.forEach(a => md += `- ${a}\n`);
    }

    fm.writeString(fm.joinPath(reportsDir, `WexSS_Summary_${timestamp}.md`), md);

    console.log(`✅ Relatórios salvos em WexSS_Reports`);
}

// ====================== FUNÇÃO PRINCIPAL ======================
async function runWexSS() {
    console.log(`🚀 WexSS v${CONFIG.version} - Scanner de Privacidade`);

    const fm = FileManager.local();
    const reportPath = fm.joinPath(fm.documentsDirectory(), CONFIG.reportFileName);

    if (!fm.fileExists(reportPath)) {
        let alert = new Alert();
        alert.title = "Arquivo não encontrado";
        alert.message = `Coloque o relatório como:\n${CONFIG.reportFileName}\nna pasta Documents do Scriptable`;
        alert.addAction("OK");
        await alert.present();
        return;
    }

    const content = fm.readString(reportPath);
    const lines = content.split("\n").filter(l => l.trim());

    console.log(`📄 Processando ${lines.length} entradas...`);

    const rawData = extractDomainsFromReport(lines);

    // Análises
    const trackersFound = rawData.allDomains.filter(d => 
        CONFIG.knownTrackers.some(t => d.includes(t)) || 
        CONFIG.highRiskKeywords.some(k => d.includes(k))
    );

    const riskyApps = rawData.apps
        .filter(app => app.domains.length > 8 || app.permissions.some(p => /location|camera|microphone/i.test(p)))
        .map(app => ({
            appName: app.appName,
            domainsCount: app.domains.length,
            permissions: app.permissions,
            riskLevel: app.domains.length > 15 ? "CRITICAL" : app.domains.length > 10 ? "HIGH" : "MEDIUM"
        }));

    const anomalies = detectAnomalies(rawData.apps);

    let analysis = {
        totalEntries: lines.length,
        totalUniqueDomains: rawData.allDomains.length,
        trackersFound,
        riskyApps,
        anomalies,
        overallRisk: "LOW"
    };

    const riskInfo = classifyRiskLevel(analysis);
    analysis.riskScore = riskInfo.riskScore;
    analysis.riskLevel = riskInfo.riskLevel;

    await generateReports(analysis, rawData);

    // Alerta final
    let finalAlert = new Alert();
    finalAlert.title = "WexSS - Análise Concluída";
    finalAlert.message = `Risco: ${analysis.riskLevel}\nTrackers: ${trackersFound.length}\nApps suspeitos: ${riskyApps.length}`;
    finalAlert.addAction("OK");
    await finalAlert.present();
}

// Inicia o scanner
runWexSS().catch(err => {
    console.error("Erro:", err);
    let a = new Alert();
    a.title = "Erro no WexSS";
    a.message = err.message || "Erro desconhecido";
    a.addAction("OK");
    a.present();
});
