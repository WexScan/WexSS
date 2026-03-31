// ================================================
// WexSS - Scanner Avançado de Relatório de Privacidade iOS
// Versão 1.5 - Com seletor de arquivo + melhor tratamento de erros
// GitHub: WexScan
// ================================================

const CONFIG = {
    version: "1.5",
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

    lines.forEach((line, index) => {
        if (!line.trim()) return;
        try {
            const entry = JSON.parse(line);
            const appName = entry.bundleIdentifier || entry.accessor?.identifier || `App_${index}`;

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
        } catch(e) {
            // Ignora linhas inválidas silenciosamente
        }
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

// ====================== ANÁLISE ======================
function classifyRisk(analysis) {
    let score = 0;
    if (analysis.trackersFound.length > 15) score += 40;
    else if (analysis.trackersFound.length > 8) score += 25;

    analysis.riskyApps.forEach(app => {
        if (app.domainsCount > 15) score += 20;
        if (app.permissions.some(p => /location|camera|microphone|contacts/i.test(p))) score += 15;
    });

    let riskLevel = "LOW";
    if (score >= 70) riskLevel = "CRITICAL";
    else if (score >= 45) riskLevel = "HIGH";
    else if (score >= 20) riskLevel = "MEDIUM";

    return { riskScore: Math.min(score, 100), riskLevel };
}

function detectAnomalies(apps) {
    return apps
        .filter(app => app.domains.length > 20 || (app.permissions.some(p => /location/i.test(p)) && app.accessCount > 40))
        .map(app => `\( {app.appName} ( \){app.domains.length} domínios)`);
}

// ====================== RELATÓRIOS ======================
async function generateReports(analysis, rawData) {
    const fm = FileManager.local();
    const reportsDir = fm.joinPath(fm.documentsDirectory(), "WexSS_Reports");
    fm.createDirectory(reportsDir, true);

    const timestamp = new Date().toISOString().slice(0,19).replace(/[:.]/g, "-");

    const fullReport = { scanDate: new Date().toISOString(), summary: analysis, apps: rawData.apps.slice(0, 40) };
    fm.writeString(fm.joinPath(reportsDir, `WexSS_Full_Report_${timestamp}.json`), JSON.stringify(fullReport, null, 2));

    let md = `# WexSS - Relatório de Privacidade iOS v${CONFIG.version}\n\n`;
    md += `**Data:** ${new Date().toLocaleString('pt-BR')}\n`;
    md += `**Risco Geral:** ${analysis.riskLevel} (Score: ${analysis.riskScore})\n\n`;
    md += `**Domínios únicos:** ${analysis.totalUniqueDomains}\n`;
    md += `**Trackers detectados:** ${analysis.trackersFound.length}\n\n`;

    md += `## Apps de Alto Risco\n`;
    analysis.riskyApps.forEach(app => md += `- **${app.appName}** → \( {app.riskLevel} ( \){app.domainsCount} domínios)\n`);

    fm.writeString(fm.joinPath(reportsDir, `WexSS_Summary_${timestamp}.md`), md);
}

// ====================== PRINCIPAL ======================
async function runWexSS() {
    console.log(`🚀 WexSS v${CONFIG.version} - Seletor de arquivo`);

    let filePath;
    try {
        // Tenta abrir o seletor permitindo qualquer tipo de arquivo
        filePath = await DocumentPicker.open(["public.item", "public.data", "public.json"]);
        console.log("Arquivo selecionado:", filePath);
    } catch (error) {
        console.error("Erro no DocumentPicker:", error);
        let alert = new Alert();
        alert.title = "Seleção cancelada ou falhou";
        alert.message = "Você cancelou a seleção ou ocorreu um erro ao abrir o seletor.\n\nTente novamente.";
        alert.addAction("OK");
        await alert.present();
        return;
    }

    const fm = FileManager.local();
    let content = "";
    try {
        content = fm.readString(filePath);
        console.log(`Arquivo lido com ${content.length} caracteres`);
    } catch (e) {
        console.error("Erro ao ler arquivo:", e);
        let alert = new Alert();
        alert.title = "Erro ao ler o arquivo";
        alert.message = "Não foi possível ler o conteúdo do arquivo selecionado.\n\nDica: Tente copiar o arquivo para o iCloud Drive e selecionar de lá.";
        alert.addAction("OK");
        await alert.present();
        return;
    }

    const lines = content.split("\n").filter(l => l.trim().length > 5); // evita linhas vazias ou muito curtas

    if (lines.length === 0) {
        let alert = new Alert();
        alert.title = "Arquivo inválido";
        alert.message = "O arquivo selecionado não parece ser um relatório de privacidade válido (NDJSON).";
        alert.addAction("OK");
        await alert.present();
        return;
    }

    console.log(`📄 Processando ${lines.length} entradas...`);

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
            riskLevel: app.domains.length > 15 ? "CRITICAL" : "HIGH"
        }));

    const anomalies = detectAnomalies(rawData.apps);

    let analysis = {
        totalEntries: lines.length,
        totalUniqueDomains: rawData.allDomains.length,
        trackersFound: trackersFound.slice(0, 30),
        riskyApps: riskyApps.slice(0, 12),
        anomalies: anomalies
    };

    const riskInfo = classifyRisk(analysis);
    analysis.riskScore = riskInfo.riskScore;
    analysis.riskLevel = riskInfo.riskLevel;

    await generateReports(analysis, rawData);

    let finalAlert = new Alert();
    finalAlert.title = "✅ Análise Concluída";
    finalAlert.message = `Risco: ${analysis.riskLevel}\nTrackers: ${analysis.trackersFound.length}\nApps suspeitos: ${analysis.riskyApps.length}\n\nRelatórios salvos em WexSS_Reports`;
    finalAlert.addAction("OK");
    await finalAlert.present();
}

runWexSS().catch(err => {
    console.error("Erro geral:", err);
    let a = new Alert();
    a.title = "Erro no WexSS";
    a.message = "Ocorreu um erro inesperado.\n\n" + (err.message || err);
    a.addAction("OK");
    a.present();
});
