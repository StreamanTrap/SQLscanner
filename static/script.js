document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-btn');
    const stopBtn = document.getElementById('stop-btn');
    const statusMessage = document.getElementById('status-message');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const progressContainer = document.getElementById('progress-container');
    const resultsContainer = document.getElementById('results-container');
    const resultsContent = document.getElementById('results-content');

    let checkInterval;

    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value;
        if (!url) {
            showStatus('Пожалуйста, введите URL.', 'error');
            return;
        }

        resetUI();
        scanBtn.style.display = 'none';
        stopBtn.style.display = 'inline-block';
        progressContainer.style.display = 'block';
        resultsContainer.style.display = 'none';
        showStatus('Запуск сканирования...', 'success');

        try {
            const response = await fetch('/api/scan_web', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            if (response.ok) {
                const data = await response.json();
                console.log('Сканирование запущено, ID:', data.scan_id);
                startCheckingStatus(data.scan_id);
            } else {
                const errorData = await response.json();
                showStatus(`Ошибка: ${errorData.error}`, 'error');
                resetUI();
            }
        } catch (error) {
            showStatus('Ошибка сети при отправке запроса на сканирование.', 'error');
            resetUI();
        }
    });

    stopBtn.addEventListener('click', async () => {
        if (!currentScanId) return;

        try {
            const response = await fetch('/api/stop_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: currentScanId })
            });
            const data = await response.json();
            console.log(data.message);
            clearInterval(checkInterval); // Остановить проверку статуса
            stopScanProcess();
        } catch (error) {
            console.error('Ошибка при остановке сканирования:', error);
        }
    });

    let currentScanId = null;

    function startCheckingStatus(scanId) {
        currentScanId = scanId;
        checkInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/scan_status');
                const status = await response.json();

                updateProgressBar(status.progress);
                progressText.textContent = `${status.progress}%`;

                if (!status.is_scanning) {
                    clearInterval(checkInterval);
                    stopScanProcess();
                    if (status.results) {
                        displayResults(status.results);
                        if (status.results.success) {
                            showStatus(`Сканирование завершено. Найдено уязвимостей: ${status.results.vulnerabilities_found}`, 'success');
                        } else {
                            showStatus(`Сканирование завершено с ошибкой: ${status.results.error}`, 'error');
                        }
                    }
                }
            } catch (error) {
                console.error('Ошибка при проверке статуса:', error);
                clearInterval(checkInterval);
                stopScanProcess();
            }
        }, 1000);
    }

    function stopScanProcess() {
        resetUI();
        showStatus('Сканирование остановлено.', 'success');
    }

    function updateProgressBar(percent) {
        progressBar.style.width = `${percent}%`;
    }

    function displayResults(results) {
        let html = `<p><strong>URL:</strong> ${results.url}</p>`;
        html += `<p><strong>Параметры:</strong> ${results.parameters.join(', ')}</p>`;
        html += `<p><strong>Всего тестов:</strong> ${results.total_tests}</p>`;
        html += `<p><strong>Найдено уязвимостей:</strong> ${results.vulnerabilities_found}</p>`;

        if (results.vulnerabilities_found > 0) {
            html += '<h3>Найденные уязвимости:</h3>';
            html += '<ul>';
            results.results.forEach(result => {
                if (result.is_vulnerable) {
                    html += `<li class="vulnerable">Параметр: ${result.parameter}, Payload: ${result.payload}, URL: <a href="${result.url}" target="_blank">${result.url}</a></li>`;
                }
            });
            html += '</ul>';
        } else {
            html += '<p class="safe">Уязвимости не найдены.</p>';
        }

        resultsContent.innerHTML = html;
        resultsContainer.style.display = 'block';
    }

    function resetUI() {
        scanBtn.style.display = 'inline-block';
        stopBtn.style.display = 'none';
        progressContainer.style.display = 'none';
        updateProgressBar(0);
        progressText.textContent = '0%';
    }

    function showStatus(message, type) {
        statusMessage.textContent = message;
        statusMessage.className = `status-message ${type}`;
    }
});