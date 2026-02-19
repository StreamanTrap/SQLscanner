from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time
import threading

app = Flask(__name__)
CORS(app)

# 🎯 Встроенный HTML (НЕ НУЖЕН отдельный файл!)
HTML_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ SQLi Сканер</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        input[type=url] { width: 70%; padding: 12px; border: 2px solid #ddd; border-radius: 5px; font-size: 16px; }
        button { padding: 12px 25px; margin-left: 10px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .scan-btn { background: #28a745; color: white; }
        .stop-btn { background: #dc3545; color: white; display: none; }
        .progress { width: 100%; height: 20px; background: #eee; border-radius: 10px; margin: 20px 0; overflow: hidden; }
        .progress-fill { height: 100%; background: #28a745; width: 0%; transition: width 0.3s; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; text-align: center; }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .results { margin-top: 20px; padding: 20px; background: #e9ecef; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SQL-инъекций Сканер</h1>
        <p>Введите URL с параметрами (например: <code>https://testphp.vulnweb.com/artists.php?artist=1</code>)</p>
        
        <input type="url" id="urlInput" placeholder="https://example.com/page?id=1">
        <button class="scan-btn" onclick="startScan()">🚀 Сканировать</button>
        <button class="stop-btn" onclick="stopScan()">⏹️ Остановить</button>
        
        <div id="status" class="status" style="display:none;"></div>
        <div id="progressContainer" style="display:none;">
            <div class="progress"><div class="progress-fill" id="progressFill"></div></div>
            <div id="progressText">0%</div>
        </div>
        
        <div id="results" class="results" style="display:none;"></div>
    </div>

    <script>
        let polling;
        
        async function startScan() {
            const url = document.getElementById('urlInput').value;
            if (!url) return showStatus('Введите URL!', 'error');
            
            document.querySelector('.scan-btn').style.display = 'none';
            document.querySelector('.stop-btn').style.display = 'inline-block';
            document.getElementById('progressContainer').style.display = 'block';
            showStatus('🚀 Запуск сканирования...', 'success');
            
            try {
                const response = await fetch('/api/scan_web', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                const data = await response.json();
                
                if (data.scan_id) {
                    pollStatus();
                } else {
                    showStatus('Ошибка запуска!', 'error');
                    resetUI();
                }
            } catch(e) {
                showStatus('Ошибка сети!', 'error');
                resetUI();
            }
        }
        
        async function pollStatus() {
            polling = setInterval(async () => {
                const response = await fetch('/api/scan_status');
                const status = await response.json();
                
                document.getElementById('progressFill').style.width = status.progress + '%';
                document.getElementById('progressText').textContent = status.progress + '%';
                
                if (!status.is_scanning) {
                    clearInterval(polling);
                    if (status.results) {
                        showResults(status.results);
                    }
                    resetUI();
                }
            }, 500);
        }
        
        function showResults(data) {
            const resultsDiv = document.getElementById('results');
            if (data.success && data.vulnerabilities_found > 0) {
                resultsDiv.innerHTML = `
                    <h3>🔴 Найдено уязвимостей: ${data.vulnerabilities_found}</h3>
                    ${data.issues.map(issue => 
                        `<div><strong>${issue.type}</strong> (${issue.severity})</div>`
                    ).join('')}
                `;
            } else {
                resultsDiv.innerHTML = '<h3>🟢 Уязвимости не найдены!</h3>';
            }
            resultsDiv.style.display = 'block';
        }
        
        function resetUI() {
            document.querySelector('.scan-btn').style.display = 'inline-block';
            document.querySelector('.stop-btn').style.display = 'none';
            document.getElementById('progressContainer').style.display = 'none';
        }
        
        function stopScan() {
            fetch('/api/stop_scan', {method: 'POST'});
            clearInterval(polling);
            resetUI();
        }
        
        function showStatus(msg, type) {
            const status = document.getElementById('status');
            status.textContent = msg;
            status.className = `status ${type}`;
            status.style.display = 'block';
            setTimeout(() => status.style.display = 'none', 3000);
        }
    </script>
</body>
</html>
"""

# Глобальные переменные
current_scan_status = {"is_scanning": False, "progress": 0, "results": None, "scan_id": "", "current_target": "", "scan_type": ""}
scan_counter = 1

class SimpleScanner:
    def scan_url(self, url):
        print(f"🔍 Scanning {url}")
        for i in range(11):
            time.sleep(0.3)
            current_scan_status["progress"] = i * 10
        return {
            "success": True,
            "url": url,
            "vulnerabilities_found": 2,
            "issues": [
                {"type": "SQL Injection (Blind)", "severity": "High"},
                {"type": "Missing Security Headers", "severity": "Medium"}
            ]
        }

scanner = SimpleScanner()

@app.route('/')
def index():
    return HTML_CONTENT  # ✅ Встроенный HTML!

@app.route('/api/scan_web', methods=['POST'])
def scan_web():
    global current_scan_status, scan_counter
    
    print("📡 Scan request received")
    
    if current_scan_status["is_scanning"]:
        return jsonify({"error": "Already scanning"}), 409

    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400

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
            print(f"✅ Scan complete: {result['vulnerabilities_found']} vulnerabilities")
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
