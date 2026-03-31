// ================================================
// WexSS - Scanner
// ================================================

const CONFIG = {
    version: "1.4",
    highRiskKeywords: ["track", "analytics", "pixel", "beacon", "ads", "log", "collect", "doubleclick", "google-analytics", "facebook", "appsflyer", "adjust", "criteo", "demdex"],
    knownTrackers: [
        "doubleclick.net", "google-analytics.com", "googletagmanager.com", "facebook.com", "fbcdn.net",
        "analytics.google.com", "adobedtm.com", "scorecardresearch.com", "appsflyer.com", "adjust.com",
        "branch.io", "app-measurement.com", "criteo.com", "demdex.net", "omtrdc.net"
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
            const appName = entry.bundleIdentifier || entry.accessor?.identifier || "Unknown App";

            if (!appsData.has(appName)) {
                appsData.set(appName, { domains: new Set(), permissions: new Set(), count: 0 });
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
        } catch(e) {}
    });

    return {
        allDomains: Array.from(domains),
        apps: Array.from(appsData.entries()).map(([name, data]) => ({
            appName: name,
            domains: Array.from(data.domains),
            permissions: Array.from(data.permissions),
            accessCount: data.count
        }))
    };
}

// ====================== ANÁLISE DE RISCO ======================
function classifyRisk(analysis) {
    let score = 0;
    const tags = [];

    if (analysis.trackersFound.length > 15) { score += 40; tags.push("Muitos trackers"); }
    else if (analysis.trackersFound.length > 8) { score += 25; tags.push("Trackers moderados"); }

    analysis.riskyApps.forEach(app => {
        if (app.domainsCount > 15) score += 20;
        if (app.permissions.some(p => /location|camera|microphone|contacts/i.test(p))) score += 15;
    });

    let riskLevel = "LOW";
    if (score >= 70) riskLevel = "CRITICAL";
    else if (score >= 45) riskLevel = "HIGH";
    else if (score >= 20) riskLevel = "MEDIUM";

    return { riskScore: Math.min(score, 100), riskLevel, tags };
}

// ====================== DETECÇÃO DE ANOMALIAS ======================
function detectAnomalies(apps) {
    const anomalies = [];
    apps.forEach(app => {
        if (app.domains.length > 20) anomalies.push(`${app.appName} acessou ${app.domains.length} domínios`);
        if (app.permissions.some(p => /location/i.test(p)) && app.accessCount > 40) {
            anomalies.push(`${app.appName} acessou localização excessivamente`);
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

    const fullReport = {
        scanDate: new Date().toISOString(),
        summary: analysis,
        apps: rawData.apps.slice(0, 40)
    };

    fm.writeString(fm.joinPath(reportsDir, `WexSS_Full_Report_${timestamp}.json`), JSON.stringify(fullReport, null, 2));

    let md = `# WexSS - Relatório de Privacidade iOS\n\n`;
    md += `**Versão:** ${CONFIG.version} | **Data:** ${new Date().toLocaleString('pt-BR')}\n\n`;
    md += `**Risco Geral:** ${analysis.riskLevel} (Score: ${analysis.riskScore})\n`;
    md += `**Domínios únicos:** ${analysis.totalUniqueDomains}\n`;
    md += `**Trackers detectados:** ${analysis.trackersFound.length}\n`;
    md += `**Apps de alto risco:** ${analysis.riskyApps.length}\n\n`;

    md += `## Apps de Alto Risco\n`;
    analysis.riskyApps.forEach(app => md += `- **${app.appName}** → \( {app.riskLevel} ( \){app.domainsCount} domínios)\n`);

    md += `\n## Trackers Encontrados\n`;
    analysis.trackersFound.forEach(t => md += `- ${t}\n`);

    if (analysis.anomalies && analysis.anomalies.length > 0) {
        md += `\n## Anomalias Detectadas\n`;
        analysis.anomalies.forEach(a => md += `- ${a}\n`);
    }

    fm.writeString(fm.joinPath(reportsDir, `WexSS_Summary_${timestamp}.md`), md);

    console.log("✅ Relatórios salvos na pasta WexSS_Reports");
}

// ====================== FUNÇÃO PRINCIPAL COM SELETOR DE ARQUIVO ======================
async function runWexSS() {
    console.log(`🚀 Iniciando WexSS v${CONFIG.version}`);

    // === NOVO: Seletor de arquivo do iOS ===
    const fm = FileManager.local();
    let filePath;

    try {
        // Abre o seletor de arquivos do iOS
        filePath = await DocumentPicker.open(["public.json", "public.text", "public.data"]);
        console.log("Arquivo selecionado:", filePath);
    } catch (error) {
        console.log("Seleção de arquivo cancelada ou falhou.");
        let alert = new Alert();
        alert.title = "Seleção cancelada";
        alert.message = "Você não selecionou nenhum arquivo.";
        alert.addAction("OK");
        await alert.present();
        return;
    }

    // Lê o conteúdo do arquivo selecionado
    let content;
    try {
        content = fm.readString(filePath);
    } catch (e) {
        let alert = new Alert();
        alert.title = "Erro ao ler arquivo";
        alert.message = "Não foi possível ler o arquivo selecionado.\nVerifique se é um arquivo .ndjson válido.";
        alert.addAction("OK");
        await alert.present();
        return;
    }

    const lines = content.split("\n").filter(l => l.trim().length > 0);

    if (lines.length === 0) {
        let alert = new Alert();
        alert.title = "Arquivo vazio";
        alert.message = "O arquivo selecionado não contém dados válidos.";
        alert.addAction("OK");
        await alert.present();
        return;
    }

    console.log(`📄 Processando ${lines.length} entradas do relatório...`);

    const rawData = extractDomainsFromReport(lines);

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
            riskLevel: app.domains.length > 15 ? "CRITICAL" : "HIGH"
        }));

    const anomalies = detectAnomalies(rawData.apps);

    let analysis = {
        totalEntries: lines.length,
        totalUniqueDomains: rawData.allDomains.length,
        trackersFound: trackersFound.slice(0, 30),
        riskyApps: riskyApps.slice(0, 12),
        anomalies: anomalies,
        overallRisk: "LOW"
    };

    const riskInfo = classifyRisk(analysis);
    analysis.riskScore = riskInfo.riskScore;
    analysis.riskLevel = riskInfo.riskLevel;

    await generateReports(analysis, rawData);

    // Alerta final
    let finalAlert = new Alert();
    finalAlert.title = "WexSS - Análise Concluída";
    finalAlert.message = `Risco Geral: ${analysis.riskLevel}\n` +
                        `Trackers: ${analysis.trackersFound.length}\n` +
                        `Apps suspeitos: ${analysis.riskyApps.length}\n\n` +
                        `Relatórios salvos em: WexSS_Reports`;
    finalAlert.addAction("OK");
    await finalAlert.present();
}

// Inicia o script
runWexSS().catch(err => {
    console.error("Erro:", err);
    let a = new Alert();
    a.title = "Erro no WexSS";
    a.message = err.message || "Ocorreu um erro inesperado.";
    a.addAction("OK");
    a.present();
});
