import sys
print(f"Запуск Python версии: {sys.version}")

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os

# Импортируем сканер логику (должен быть в той же директории)
try:
    from scanner_logic import web_scanner, current_scan_status, scan_counter
except ImportError:
    print("ВНИМАНИЕ: scanner_logic.py не найден. Создайте этот файл или установите зависимости.")
    # Создаем заглушки для GitHub демо
    class DummyScanner:
        def scan_url(self, url):
            import time
            time.sleep(2)  # Имитация сканирования
            return {
                "success": True,
                "url": url,
                "vulnerabilities_found": 3,
                "issues": [
                    {"type": "Missing Security Headers", "severity": "Medium"},
                    {"type": "XSS Vulnerability", "severity": "High"},
                    {"type": "Open Redirect", "severity": "Low"}
                ]
            }
    
    web_scanner = DummyScanner()
    current_scan_status = {"is_scanning": False, "progress": 0, "results": None, "scan_id": "", "current_target": "", "scan_type": ""}
    scan_counter = 1

app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan_web', methods=['POST'])
def scan_web_url():
    global current_scan_status, scan_counter

    if current_scan_status["is_scanning"]:
        return jsonify({"error": "Сканирование уже запущено.", "scan_id": current_scan_status["scan_id"]}), 409

    try:
        data = request.get_json()
        url_to_scan = data.get('url')

        if not url_to_scan:
            return jsonify({"error": "Не указан URL для сканирования."}), 400

        # Валидация URL
        if not url_to_scan.startswith(('http://', 'https://')):
            url_to_scan = 'https://' + url_to_scan

        current_scan_status.update({
            "is_scanning": True,
            "progress": 0,
            "results": None,
            "scan_id": f"webscan-{scan_counter}",
            "current_target": url_to_scan,
            "scan_type": "web"
        })
        scan_counter += 1

        print(f"Начато веб-сканирование для: {url_to_scan} (ID: {current_scan_status['scan_id']})")

        # Имитация прогресса для демонстрации
        import time
        for i in range(11):
            time.sleep(0.2)
            current_scan_status["progress"] = i * 10

        scan_result = web_scanner.scan_url(url_to_scan)

        current_scan_status.update({
            "results": scan_result,
            "progress": 100,
            "is_scanning": False
        })

        print(f"Веб-сканирование завершено для {url_to_scan}")
        return jsonify({
            "message": "Сканирование завершено.",
            "scan_id": current_scan_status["scan_id"], 
            "results": scan_result
        }), 200

    except Exception as e:
        print(f"Ошибка в /api/scan_web: {e}")
        current_scan_status.update({
            "results": {"error": f"Ошибка: {str(e)}", "success": False},
            "is_scanning": False
        })
        return jsonify({"error": "Серверная ошибка", "details": str(e)}), 500

@app.route('/api/scan_status', methods=['GET'])
def scan_status():
    return jsonify(current_scan_status)

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    global current_scan_status
    scan_id_to_stop = request.get_json().get("scan_id")

    if not scan_id_to_stop or scan_id_to_stop != current_scan_status.get("scan_id"):
        return jsonify({"message": "Нет активного сканирования с таким ID."}), 400

    if not current_scan_status["is_scanning"]:
        return jsonify({"message": "Сканирование не запущено."}), 400

    print(f"Остановка сканирования {current_scan_status['scan_id']}")
    current_scan_status["is_scanning"] = False
    current_scan_status["progress"] = 0
    current_scan_status["results"] = {
        "scan_id": current_scan_status["scan_id"], 
        "status": "stopped",
        "message": "Сканирование остановлено пользователем."
    }

    return jsonify({"message": "Сканирование остановлено.", "scan_id": current_scan_status["scan_id"]})

# Добавляем маршрут для статических файлов с правильными заголовками
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == '__main__':
    # Создаем необходимые директории
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    print("Сервер запускается на http://0.0.0.0:7000")
    print("Для GitHub Pages/Heroku добавьте requirements.txt и Procfile")
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 7000)), debug=False)
