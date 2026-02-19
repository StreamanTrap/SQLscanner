// static/script.js - ИСПРАВЛЕННАЯ ВЕРСИЯ
document.addEventListener('DOMContentLoaded', () => {
    console.log('🔧 JS загружен, инициализация...');
    
    // Проверяем наличие всех элементов
    const elements = {
        urlInput: document.getElementById('url-input'),
        scanBtn: document.getElementById('scan-btn'),
        stopBtn: document.getElementById('stop-btn'),
        statusMessage: document.getElementById('status-message'),
        progressContainer: document.getElementById('progress-container'),
        progressText: document.getElementById('progress-text'),
        progressBar: document.querySelector('#progress-bar .progress-fill') || document.getElementById('progress-bar'),
        resultsContainer: document.getElementById('results-container'),
        resultsContent: document.getElementById('results-content')
    };

    // Если элементы не найдены - выходим
    if (!elements.scanBtn || !elements.urlInput) {
        console.error('❌ Критические элементы не найдены!');
        return;
    }

    console.log('✅ Все элементы найдены');

    let checkInterval;
    let currentScanId = null;

    // Обработчик кнопки СКАНИРОВАТЬ
    elements.scanBtn.addEventListener('click', async () => {
        const url = elements.urlInput.value.trim();
        console.log('🚀 Запуск сканирования:', url);
        
        if (!url) {
            showStatus('Введите URL для сканирования!', 'error');
            return;
        }

        // Сбрасываем UI
        resetUI();
        elements.scanBtn.style.display = 'none';
        elements.stopBtn.style.display = 'inline-block';
        elements.progressContainer.style.display = 'block';
        showStatus('Запуск сканирования...', 'info');

        try {
            const response = await fetch('/api/scan_web', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();
            console.log('📡 Ответ сервера:', data);

            if (response.ok && data.scan_id) {
                currentScanId = data.scan_id;
                startStatusPolling();
            } else {
                showStatus(data.error || 'Ошибка запуска сканирования', 'error');
                resetUI();
            }
        } catch (error) {
            console.error('🌐 Ошибка сети:', error);
            showStatus('Ошибка соединения с сервером', 'error');
            resetUI();
        }
    });

    // Обработчик кнопки ОСТАНОВИТЬ
    elements.stopBtn.addEventListener('click', async () => {
        if (!currentScanId) return;
        
        console.log('⏹️ Запрос остановки:', currentScanId);
        
        try {
            await fetch('/api/stop_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: currentScanId })
            });
            clearInterval(checkInterval);
            stopScanProcess();
        } catch (error) {
            console.error('Ошибка остановки:', error);
        }
    });

    // ОПРОС СТАТУСА (каждую секунду)
    function startStatusPolling() {
        checkInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/scan_status');
                const status = await response.json();
                console.log('📊 Статус:', status);

                // Обновляем прогресс
                const progress = Math.max(0, Math.min(100, status.progress || 0));
                updateProgress(progress);
                elements.progressText.textContent = `${progress}%`;

                // Если завершено
                if (!status.is_scanning) {
                    clearInterval(checkInterval);
                    currentScanId = null;
                    
                    if (status.results) {
                        displayResults(status.results);
                        const vulnCount = status.results.vulnerabilities_found || 0;
                        showStatus(`✅ Сканирование завершено. Уязвимостей: ${vulnCount}`, 'success');
                    }
                    resetUI();
                }
            } catch (error) {
                console.error('Ошибка опроса статуса:', error);
                clearInterval(checkInterval);
                showStatus('Ошибка проверки статуса', 'error');
                resetUI();
            }
        }, 800); // 0.8 секунды для плавности
    }

    function updateProgress(percent) {
        if (elements.progressBar) {
            elements.progressBar.style.width = `${percent}%`;
        }
    }

    function displayResults(results) {
        let html = `
            <div class="result-summary">
                <div class="vuln-badge">${results.vulnerabilities_found || 0}</div>
                <div class="result-info">
                    <p><strong>🎯 Цель:</strong> ${results.url || 'Неизвестно'}</p>
                    <p><strong>⏱️ Статус:</strong> ${results.success ? '✅ Успешно' : '❌ Ошибка'}</p>
                </div>
            </div>
        `;

        if (results.success && results.vulnerabilities_found > 0) {
            html += '<div class="issues-list"><h4>🔴 Найденные уязвимости:</h4>';
            // Универсальный рендер результатов
            const issues = results.issues || results.results || results.vulnerabilities || [];
            issues.forEach((issue, index) => {
                html += `
                    <div class="issue-card vulnerable">
                        <span class="issue-severity">${issue.severity || 'High'}</span>
                        <div>
                            <strong>${issue.type || `Уязвимость #${index+1}`}</strong>
                            <p>${issue.description || issue.message || 'Подробности недоступны'}</p>
                        </div>
                    </div>
                `;
            });
            html += '</div>';
        } else {
            html += '<div class="safe-message">🟢 Критических уязвимостей не найдено</div>';
        }

        elements.resultsContent.innerHTML = html;
        elements.resultsContainer.style.display = 'block';
    }

    function resetUI() {
        elements.scanBtn.style.display = 'inline-block';
        elements.stopBtn.style.display = 'none';
        if (elements.progressContainer) elements.progressContainer.style.display = 'none';
        if (elements.progressText) elements.progressText.textContent = '0%';
        updateProgress(0);
        currentScanId = null;
    }

    function showStatus(message, type = 'info') {
        if (elements.statusMessage) {
            elements.statusMessage.textContent = message;
            elements.statusMessage.className = `status-message ${type}`;
            elements.statusMessage.style.display = 'block';
            
            // Авто-скрытие через 5 сек
            setTimeout(() => {
                elements.statusMessage.style.display = 'none';
            }, 5000);
        }
        console.log(`[${type.toUpperCase()}] ${message}`);
    }

    // Enter в поле запускает сканирование
    elements.urlInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            elements.scanBtn.click();
        }
    });

    console.log('🎮 Сканер готов к работе!');
});
