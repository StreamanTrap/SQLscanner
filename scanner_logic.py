from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import time
import threading

# ✅ ИМПОРТ ИСПРАВЛЕН
from scanner_logic import web_scanner, current_scan_status, scan_counter

app = Flask(__name__, template_folder='templates')
CORS(app)
app.logger.setLevel(10)  # DEBUG логи

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan_web', methods=['POST'])
def scan_web():
    global current_scan_status, scan_counter
    
    print("📡 ПОЛУЧЕН ЗАПРОС /api/scan_web")
    
    if current_scan_status["is_scanning"]:
        return jsonify({"error": "Уже сканируется"}), 409

    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    current_scan_status.update({
        "is_scanning": True, "progress": 0, "results": None,
        "scan_id": f"scan-{scan_counter}", "current_target": url
    })
    scan_counter += 1
    
    print(f"🚀 СТАРТ СКАНИРОВАНИЯ: {url}")
    
    def run_scan():
        try:
            result = web_scanner.scan_url(url)
            current_scan_status.update({"results": result, "progress": 100, "is_scanning": False})
            print(f"✅ РЕЗУЛЬТАТ: {result.get('vulnerabilities_found', 0)} уязвимостей")
        except Exception as e:
            print(f"❌ ОШИБКА: {e}")
            current_scan_status.update({"results": {"success": False, "error": str(e)}, "is_scanning": False})

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"message": "Запущено", "scan_id": current_scan_status["scan_id"]}), 200

@app.route('/api/scan_status')
def scan_status():
    return jsonify(current_scan_status)

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    current_scan_status["is_scanning"] = False
    return jsonify({"message": "Остановлено"}), 200

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    print("🌐 http://localhost:7000")
    print("✅ НАСТОЯЩИЙ SQLI СКАНЕР ГОТОВ!")
    app.run(host='0.0.0.0', port=7000, debug=True)
