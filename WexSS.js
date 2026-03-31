// ================================================
// WexSS - WexScan
// ================================================

const CONFIG = {
    version: "2.4",
    appName: "WexSS"
};

// ====================== EXTRAÇÃO DE DADOS ======================
function extract_domains(lines) {
    const domains = new Set();
    const appsMap = new Map();

    lines.forEach(function(line) {
        if (!line.trim()) return;
        try {
            var entry = JSON.parse(line);
            var appName = entry.bundleIdentifier || (entry.accessor && entry.accessor.identifier) || "Unknown App";

            if (!appsMap.has(appName)) {
                appsMap.set(appName, { domains: new Set(), permissions: new Set(), count: 0 });
            }
            var app = appsMap.get(appName);
            app.count++;

            if (entry.domain) {
                var d = entry.domain.toLowerCase().trim();
                domains.add(d);
                app.domains.add(d);
            }
            if (entry.url) {
                try {
                    var host = new URL(entry.url).hostname.toLowerCase();
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
        apps: Array.from(appsMap.entries()).map(function(entry) {
            var name = entry[0];
            var data = entry[1];
            return {
                appName: name,
                domainsCount: data.domains.size,
                permissions: Array.from(data.permissions),
                accessCount: data.count
            };
        })
    };
}

function sanitize_inputs(data) {
    return data.filter(function(line) {
        return line && typeof line === "string" && line.trim().length > 5;
    });
}

function validate_input_data(lines) {
    return lines.length > 5;
}

// ====================== ANÁLISE DE RISCO ======================
function classify_risk_level(data) {
    var score = 0;
    if (data.trackersCount > 15) score += 40;
    else if (data.trackersCount > 8) score += 25;

    data.riskyApps.forEach(function(app) {
        if (app.domainsCount > 15) score += 20;
        if (app.permissions.some(function(p) { return /location|camera|microphone|contacts/i.test(p); })) score += 15;
    });

    var riskLevel = score >= 70 ? "CRITICAL" : score >= 45 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";
    return { riskScore: Math.min(score, 100), riskLevel: riskLevel };
}

function detect_anomalies(apps) {
    return apps.filter(function(app) {
        return app.domainsCount > 20 || 
               (app.permissions.some(function(p) { return /location/i.test(p); }) && app.accessCount > 40);
    }).map(function(app) {
        return app.appName + " (" + app.domainsCount + " domínios)";
    });
}

function generate_recommendation(analysis) {
    if (analysis.riskLevel === "CRITICAL") 
        return "Recomendação urgente: Revise permissões de apps com muitos trackers e acesso sensível.";
    if (analysis.riskLevel === "HIGH") 
        return "Atenção: Considere limitar permissões de apps suspeitos.";
    return "Nível de privacidade aceitável. Monitore trackers regularmente.";
}

// ====================== RELATÓRIOS ======================
function generate_json_report(results) {
    var fm = FileManager.local();
    var dir = fm.joinPath(fm.documentsDirectory(), "WexSS_Reports");
    fm.createDirectory(dir, true);
    var ts = new Date().toISOString().slice(0,19).replace(/[:.]/g, "-");
    fm.writeString(fm.joinPath(dir, "WexSS_Full_Report_" + ts + ".json"), JSON.stringify(results, null, 2));
}

function generate_markdown_report(analysis) {
    var fm = FileManager.local();
    var dir = fm.joinPath(fm.documentsDirectory(), "WexSS_Reports");
    fm.createDirectory(dir, true);
    var ts = new Date().toISOString().slice(0,19).replace(/[:.]/g, "-");

    var md = "# WexSS - Relatório Ultra Profissional v" + CONFIG.version + "\n\n";
    md += "**Data:** " + new Date().toLocaleString("pt-BR") + "\n";
    md += "**Risco Geral:** " + analysis.riskLevel + " (Score: " + analysis.riskScore + ")\n\n";
    md += "**Domínios únicos:** " + analysis.totalDomains + "\n";
    md += "**Trackers detectados:** " + analysis.trackersCount + "\n\n";

    md += "## Apps de Alto Risco\n";
    analysis.riskyApps.forEach(function(app) {
        md += "- **" + app.appName + "** → " + app.riskLevel + " (" + app.domainsCount + " domínios)\n";
    });

    fm.writeString(fm.joinPath(dir, "WexSS_Summary_" + ts + ".md"), md);
}

// ====================== DASHBOARD ======================
function showProfessionalDashboard(analysis) {
    var html = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WexSS Dashboard v${CONFIG.version}</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0a0a0a; color: #eee; margin: 0; padding: 20px; }
        .card { background: #1f1f1f; border-radius: 18px; padding: 20px; margin: 15px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 14px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #2a2a2a; }
    </style>
</head>
<body>
    <h1 style="text-align:center;color:#00ff9d;">WexSS Dashboard v${CONFIG.version}</h1>
    
    <div class="card">
        <h2>Risco Geral: ${analysis.riskLevel} (Score ${analysis.riskScore})</h2>
        <p>Trackers: ${analysis.trackersCount} | Domínios: ${analysis.totalDomains}</p>
    </div>

    <div class="card">
        <h3>Apps de Alto Risco</h3>
        <table>
            <tr><th>App</th><th>Domínios</th><th>Risco</th></tr>
            ${analysis.riskyApps.map(function(app) {
                return "<tr><td>" + app.appName + "</td><td>" + app.domainsCount + "</td><td>" + app.riskLevel + "</td></tr>";
            }).join("")}
        </table>
    </div>
</body>
</html>`;

    var webview = new WebView();
    webview.loadHTML(html);
    webview.present();
}

// ====================== EXECUÇÃO PRINCIPAL ======================
async function run_full_scan() {
    console.log("🚀 Iniciando WexSS v" + CONFIG.version);

    var filePath;
    try {
        filePath = await DocumentPicker.openFile();
    } catch (e) {
        var a = new Alert();
        a.title = "Seleção cancelada";
        a.message = "Nenhum arquivo foi selecionado.";
        a.addAction("OK");
        await a.present();
        return;
    }

    var fm = FileManager.local();
    var content = fm.readString(filePath);
    var lines = sanitize_inputs(content.split("\n"));

    if (!validate_input_data(lines)) {
        var a = new Alert();
        a.title = "Arquivo inválido";
        a.message = "O arquivo selecionado não parece ser um relatório de privacidade válido.";
        a.addAction("OK");
        await a.present();
        return;
    }

    var rawData = extract_domains(lines);

    var trackersCount = rawData.allDomains.filter(function(d) {
        return ["doubleclick","google-analytics","facebook","appsflyer","adjust","criteo"].some(function(t) {
            return d.includes(t);
        });
    }).length;

    var riskyApps = rawData.apps
        .filter(function(app) { return app.domainsCount > 10; })
        .map(function(app) {
            return {
                appName: app.appName,
                domainsCount: app.domainsCount,
                riskLevel: app.domainsCount > 15 ? "CRITICAL" : "HIGH"
            };
        });

    var analysis = {
        totalDomains: rawData.allDomains.length,
        trackersCount: trackersCount,
        riskyApps: riskyApps,
        riskScore: 0,
        riskLevel: "LOW"
    };

    var riskInfo = classify_risk_level(analysis);
    analysis.riskScore = riskInfo.riskScore;
    analysis.riskLevel = riskInfo.riskLevel;

    generate_json_report(analysis);
    generate_markdown_report(analysis);
    showProfessionalDashboard(analysis);

    console.log("✅ Análise concluída com sucesso.");
}

run_full_scan().catch(function(err) {
    console.error("Erro:", err);
    var a = new Alert();
    a.title = "Erro no WexSS";
    a.message = err.message || "Erro inesperado.";
    a.addAction("OK");
    a.present();
});
