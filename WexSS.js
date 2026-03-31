// ================================================
// WexSS - WexScan Privacy Analyzer
// v2.7 - Versão Simples e Estável para Scriptable
// GitHub: WexScan
// ================================================

const CONFIG = {
    version: "2.7"
};

async function main() {
    console.log("🚀 Iniciando WexSS v" + CONFIG.version);

    // Selecionar arquivo
    var filePath;
    try {
        filePath = await DocumentPicker.openFile();
    } catch (e) {
        var alert1 = new Alert();
        alert1.title = "Cancelado";
        alert1.message = "Nenhum arquivo foi selecionado.";
        alert1.addAction("OK");
        await alert1.present();
        return;
    }

    // Ler arquivo
    var fm = FileManager.local();
    var content = fm.readString(filePath);
    var lines = content.split("\n");

    var validLines = [];
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (line.length > 10) {
            validLines.push(line);
        }
    }

    if (validLines.length < 5) {
        var alert2 = new Alert();
        alert2.title = "Arquivo inválido";
        alert2.message = "O arquivo selecionado não parece ser um relatório de privacidade válido.";
        alert2.addAction("OK");
        await alert2.present();
        return;
    }

    // Processamento simples
    var domainCount = 0;
    var trackerCount = 0;
    var riskyAppList = [];

    var trackerWords = ["doubleclick", "google-analytics", "facebook", "appsflyer", "adjust", "criteo"];

    for (var j = 0; j < validLines.length; j++) {
        try {
            var entry = JSON.parse(validLines[j]);

            if (entry.domain) {
                domainCount++;
                var lowerDomain = entry.domain.toLowerCase();
                for (var k = 0; k < trackerWords.length; k++) {
                    if (lowerDomain.indexOf(trackerWords[k]) !== -1) {
                        trackerCount++;
                        break;
                    }
                }
            }

            if (entry.bundleIdentifier) {
                if (riskyAppList.indexOf(entry.bundleIdentifier) === -1) {
                    riskyAppList.push(entry.bundleIdentifier);
                }
            }
        } catch(e) {}
    }

    var riskLevel = "LOW";
    var riskScore = 30;

    if (trackerCount > 15) {
        riskLevel = "CRITICAL";
        riskScore = 85;
    } else if (trackerCount > 8) {
        riskLevel = "HIGH";
        riskScore = 60;
    } else if (trackerCount > 3) {
        riskLevel = "MEDIUM";
        riskScore = 40;
    }

    // Mostrar resultado simples
    var resultText = "WexSS v" + CONFIG.version + "\n\n" +
                     "Risco Geral: " + riskLevel + "\n" +
                     "Score: " + riskScore + "\n\n" +
                     "Trackers encontrados: " + trackerCount + "\n" +
                     "Domínios únicos: " + domainCount + "\n" +
                     "Apps detectados: " + riskyAppList.length;

    var alert = new Alert();
    alert.title = "✅ Análise Concluída";
    alert.message = resultText;
    alert.addAction("OK");
    await alert.present();

    console.log("✅ Análise finalizada.");
}

main().catch(function(error) {
    console.error(error);
    var errorAlert = new Alert();
    errorAlert.title = "Erro no WexSS";
    errorAlert.message = "Ocorreu um erro:\n" + error;
    errorAlert.addAction("OK");
    errorAlert.present();
});
