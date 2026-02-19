import sys
print(f"Запуск Python версии: {sys.version}")

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os

from scanner_logic import web_scanner, current_scan_status, scan_counter

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')

CORS(app)


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

        current_scan_status["is_scanning"] = True
        current_scan_status["progress"] = 0
        current_scan_status["results"] = None
        current_scan_status["scan_id"] = f"webscan-{scan_counter}"
        current_scan_status["current_target"] = "url_to_scan"
        current_scan_status["scan_type"] = "web"
        scan_counter += 1

        print(f"Начато веб-сканирование для: {url_to_scan} (ID: {current_scan_status['scan_id']})")

        scan_result = web_scanner.scan_url(url_to_scan)

        if scan_result.get("success"):
            current_scan_status["results"] = scan_result
            current_scan_status["progress"] = 100
            current_scan_status["is_scanning"] = False
            print(f"Веб-сканирование успешно завершено для {url_to_scan}. Найдено уязвимостей: {scan_result.get('vulnerabilities_found')}")
            return jsonify({"message": "Сканирование веб-URL завершено.", "scan_id": current_scan_status["scan_id"], "results": scan_result}), 200
        else:
            current_scan_status["results"] = scan_result
            current_scan_status["is_scanning"] = False
            print(f"Ошибка при веб-сканировании {url_to_scan}: {scan_result.get('error')}")
            return jsonify({"message": "Сканирование веб-URL завершено с ошибкой.", "scan_id": current_scan_status["scan_id"], "results": scan_result, "error": scan_result.get('error')}), 500

    except Exception as e:
        print(f"Непредвиденная ошибка в /api/scan_web: {e}")
        current_scan_status["results"] = {"error": f"Серверная ошибка: {e}", "success": False}
        current_scan_status["is_scanning"] = False
        return jsonify({"error": "Серверная ошибка при обработке запроса.", "details": str(e)}), 500

@app.route('/api/scan_status', methods=['GET'])
def scan_status():

    return jsonify(current_scan_status)

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():

    global current_scan_status
    scan_id_to_stop = request.get_json().get("scan_id")

    if not scan_id_to_stop or scan_id_to_stop != current_scan_status.get("scan_id"):
        return jsonify({"message": "Нет активного сканирования с таким ID для остановки."}), 400

    if not current_scan_status["is_scanning"]:
        return jsonify({"message": "Сканирование не запущено."}), 400

    print(f"--- Пользователь запросил остановку сканирования {current_scan_status['scan_id']} ---")

    current_scan_status["is_scanning"] = False

    if current_scan_status["results"] is None:
         current_scan_status["results"] = {"scan_id": current_scan_status["scan_id"], "status": "stopped_requested", "message": "Запрос на остановку получен, сканирование прервано."}
         current_scan_status["progress"] = 0

    return jsonify({"message": "Запрос на остановку сканирования отправлен.", "scan_id": current_scan_status["scan_id"]})

if __name__ == '__main__':

    if not os.path.exists('templates'):
        os.makedirs('templates')
    if not os.path.exists('static'):
        os.makedirs('static')

    app.run(debug=True, port=7000)