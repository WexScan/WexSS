// ================================================
// WexSS - WexScan Privacy Analyzer
// v2.6 - Versão Segura e Estável
// GitHub: WexScan
// ================================================

const CONFIG = {
    version: "2.6"
};

// ====================== FUNÇÕES PRINCIPAIS ======================
function extractData(lines) {
    var domains = new Set();
    var appsMap = new Map();

    lines.forEach(function(line) {
        if (!line || !line.trim()) return;
        try {
            var entry = JSON.parse(line);
            var appName = entry.bundleIdentifier || 
                         (entry.accessor && entry.accessor.identifier) || 
                         "Unknown App";

            if (!appsMap.has(appName)) {
                appsMap.set(appName, { 
                    domains: new Set(), 
                    permissions: [], 
                    count: 0 
                });
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
                var perm = entry.tccService || entry.permission;
                if (!app.permissions.includes(perm)) {
                    app.permissions.push(perm);
                }
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
                permissions: data.permissions,
                accessCount: data.count
            };
        })
    };
}

// ====================== ANÁLISE ======================
function analyzeRisk(rawData) {
    var trackersCount = 0;
    var trackerKeywords = ["doubleclick", "google-analytics", "facebook", "appsflyer", "adjust", "criteo"];

    rawData.allDomains.forEach(function(domain) {
        for (var i = 0; i < trackerKeywords.length; i++) {
            if (domain.includes(trackerKeywords[i])) {
                trackersCount++;
                break;
            }
        }
    });

    var riskyApps = [];
    rawData.apps.forEach(function(app) {
        if (app.domainsCount > 10) {
            riskyApps.push({
                appName: app.appName,
                domainsCount: app.domainsCount,
                riskLevel: app.domainsCount > 15 ? "CRITICAL" : "HIGH"
            });
        }
    });

    var score = trackersCount > 15 ? 75 : trackersCount > 8 ? 50 : 25;
    var riskLevel = score >= 70 ? "CRITICAL" : score >= 45 ? "HIGH" : "MEDIUM";

    return {
        totalDomains: rawData.allDomains.length,
        trackersCount: trackersCount,
        riskyApps: riskyApps,
        riskScore: score,
        riskLevel: riskLevel
    };
}

// ====================== DASHBOARD ======================
function showDashboard(analysis) {
    var html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WexSS v${CONFIG.version}</title>
    <style>
        body { font-family: system-ui; background: #111; color: #ddd; padding: 20px; }
        .card { background: #1f1f1f; padding: 20px; border-radius: 12px; margin: 15px 0; }
        h1 { color: #0f0; text-align: center; }
    </style>
</head>
<body>
    <h1>WexSS v${CONFIG.version}</h1>
    <div class="card">
        <h2>Risco: ${analysis.riskLevel} (Score: ${analysis.riskScore})</h2>
        <p>Trackers encontrados: ${analysis.trackersCount}</p>
        <p>Domínios únicos: ${analysis.totalDomains}</p>
    </div>
    <div class="card">
        <h3>Apps de Alto Risco (${analysis.riskyApps.length})</h3>
        ${analysis.riskyApps.map(function(app) {
            return "<p>• " + app.appName + " (" + app.domainsCount + " domínios) - " + app.riskLevel + "</p>";
        }).join("")}
    </div>
</body>
</html>`;

    var wv = new WebView();
    wv.loadHTML(html);
    wv.present();
}

// ====================== EXECUÇÃO ======================
async function main() {
    console.log("🚀 Iniciando WexSS v" + CONFIG.version);

    var filePath;
    try {
        filePath = await DocumentPicker.openFile();
    } catch (e) {
        var alert = new Alert();
        alert.title = "Cancelado";
        alert.message = "Nenhum arquivo selecionado.";
        alert.addAction("OK");
        await alert.present();
        return;
    }

    var fm = FileManager.local();
    var content = fm.readString(filePath);
    var lines = content.split("\n").filter(function(l) { 
        return l && l.trim().length > 10; 
    });

    if (lines.length < 5) {
        var a = new Alert();
        a.title = "Erro";
        a.message = "Arquivo inválido ou vazio.";
        a.addAction("OK");
        await a.present();
        return;
    }

    var rawData = extractData(lines);
    var analysis = analyzeRisk(rawData);

    showDashboard(analysis);

    console.log("✅ Análise finalizada.");
}

main().catch(function(err) {
    console.error(err);
    var a = new Alert();
    a.title = "Erro no WexSS";
    a.message = "Ocorreu um erro.\n\n" + (err.message || err);
    a.addAction("OK");
    a.present();
});
