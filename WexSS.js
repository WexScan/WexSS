// ================================================
// WexSS - Scanner de Relatório de Privacidade iOS
// Versão 1.6 - Compatível com Scriptable
// GitHub: WexScan
// ================================================

const CONFIG = {
    version: "1.6",
    highRiskKeywords: ["track", "analytics", "pixel", "beacon", "ads", "log", "collect", "doubleclick", "google-analytics", "facebook", "appsflyer", "adjust", "criteo"],
    knownTrackers: [
        "doubleclick.net", "google-analytics.com", "googletagmanager.com", "facebook.com", "fbcdn.net",
        "analytics.google.com", "adobedtm.com", "scorecardresearch.com", "appsflyer.com", "adjust.com",
        "branch.io", "app-measurement.com", "criteo.com", "demdex.net"
    ]
};

// ====================== EXTRAÇÃO DE DADOS ======================
function extractData(lines) {
    const domains = new Set();
    const apps = new Map();

    lines.forEach(line => {
        if (!line.trim()) return;
        try {
            const entry = JSON.parse(line);
            const appName = entry.bundleIdentifier || entry.accessor?.identifier || "Unknown App";

            if (!apps.has(appName)) {
                apps.set(appName, { domains: new Set(), permissions: new Set(), count: 0 });
            }
            const app = apps.get(appName);
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
        apps: Array.from(apps.entries()).map(([name, data]) => ({
            appName: name,
            domainsCount: data.domains.size,
            permissions: Array.from(data.permissions),
            accessCount: data.count
        }))
    };
}

// ====================== ANÁLISE ======================
function analyzeRisk(data) {
    const trackers = data.allDomains.filter(d => 
        CONFIG.knownTrackers.some(t => d.includes(t)) ||
        CONFIG.highRiskKeywords.some(k => d.includes(k))
    );

    const riskyApps = data.apps
        .filter(app => app.domainsCount > 10 || app.permissions.some(p => /location|camera|microphone/i.test(p)))
        .map(app => ({
            appName: app.appName,
            domainsCount: app.domainsCount,
            riskLevel: app.domainsCount > 15 ? "CRITICAL" : "HIGH"
        }));

    let score = trackers.length > 12 ? 70 : trackers.length > 6 ? 45 : 20;
    let riskLevel = score >= 70 ? "CRITICAL" : score >= 45 ? "HIGH" : "MEDIUM";

    return {
        riskLevel: riskLevel,
        riskScore: score,
        trackersCount: trackers.length,
        riskyApps: riskyApps.slice(0, 10),
        totalDomains: data.allDomains.length
    };
}

// ====================== RELATÓRIOS ======================
async function saveReports(analysis) {
    const fm = FileManager.local();
    const dir = fm.joinPath(fm.documentsDirectory(), "WexSS_Reports");
    fm.createDirectory(dir, true);

    const ts = new Date().toISOString().slice(0,19).replace(/[:.]/g, "-");

    // JSON
    fm.writeString(fm.joinPath(dir, `WexSS_Report_${ts}.json`), JSON.stringify(analysis, null, 2));

    // Markdown simples
    let md = `# WexSS Relatório v${CONFIG.version}\n\n`;
    md += `Data: ${new Date().toLocaleString('pt-BR')}\n`;
    md += `Risco: ${analysis.riskLevel}\n`;
    md += `Trackers: ${analysis.trackersCount}\n`;
    md += `Domínios: ${analysis.totalDomains}\n\n`;

    md += `## Apps de Alto Risco\n`;
    analysis.riskyApps.forEach(a => md += `- \( {a.appName} ( \){a.domainsCount} domínios)\n`);

    fm.writeString(fm.joinPath(dir, `WexSS_Summary_${ts}.md`), md);
}

// ====================== EXECUÇÃO ======================
async function main() {
    console.log(`🚀 WexSS v${CONFIG.version} iniciado`);

    let filePath;
    try {
        filePath = await DocumentPicker.openFile();   // Usa openFile() - mais simples e compatível
    } catch (e) {
        let a = new Alert();
        a.title = "Seleção cancelada";
        a.message = "Você não selecionou nenhum arquivo.";
        a.addAction("OK");
        await a.present();
        return;
    }

    const fm = FileManager.local();
    let content;
    try {
        content = fm.readString(filePath);
    } catch (e) {
        let a = new Alert();
        a.title = "Erro ao ler arquivo";
        a.message = "Não consegui ler o arquivo.\n\nDica: Salve o relatório no iCloud Drive e selecione de lá.";
        a.addAction("OK");
        await a.present();
        return;
    }

    const lines = content.split("\n").filter(l => l.trim().length > 10);

    if (lines.length < 5) {
        let a = new Alert();
        a.title = "Arquivo inválido";
        a.message = "O arquivo selecionado não parece ser um relatório de privacidade do iOS.";
        a.addAction("OK");
        await a.present();
        return;
    }

    const data = extractData(lines);
    const analysis = analyzeRisk(data);

    await saveReports(analysis);

    let success = new Alert();
    success.title = "✅ Análise Concluída";
    success.message = `Risco: ${analysis.riskLevel}\nTrackers: ${analysis.trackersCount}\nApps suspeitos: ${analysis.riskyApps.length}\n\nRelatórios salvos em WexSS_Reports`;
    success.addAction("OK");
    await success.present();
}

main().catch(err => {
    console.error(err);
    let a = new Alert();
    a.title = "Erro";
    a.message = "Ocorreu um erro inesperado.\n\n" + (err.message || err);
    a.addAction("OK");
    a.present();
});
