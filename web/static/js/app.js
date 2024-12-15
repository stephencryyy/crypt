// web/static/js/app.js

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');
    const createChatForm = document.getElementById('create-chat-form');
    const joinChatForm = document.getElementById('join-chat-form');
    const sendMessageButton = document.getElementById('send-message-button');
    const messageInput = document.getElementById('message');
    const messagesDiv = document.getElementById('messages');
    const logoutButton = document.getElementById('logout-button');
    const deleteChatButton = document.getElementById('delete-chat-btn'); // Новые кнопки
    const fileUploadForm = document.getElementById('file-upload-form');
    const fileInput = document.getElementById('file-input');
    const filesDiv = document.getElementById('files');

    let socket = null;

    // Функция для получения параметра из URL
    function getQueryParam(param) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(param);
    }

    const roomID = getQueryParam('room_id');

    if (roomID) {
        connectWebSocket(roomID);
    }

        // Функция экранирования HTML (предотвращение XSS)
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    // Обработка регистрации
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(registerForm);
            const response = await fetch('/register', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            const messageDiv = document.getElementById('message');
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                if (response.ok) {
                    messageDiv.innerHTML = `<p style="color: green;">${result.message}</p>`;
                    registerForm.reset();
                } else {
                    messageDiv.innerHTML = `<p style="color: red;">${result.error}</p>`;
                }
            }
        });
    }

    // Обработка входа
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const response = await fetch('/login', {
                method: 'POST',
                body: formData
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                const messageDiv = document.getElementById('message');
                if (response.ok) {
                    window.location.href = '/messi';
                } else {
                    messageDiv.innerHTML = `<p style="color: red;">${result.error}</p>`;
                }
            }
        });
    }

    // Обработка создания комнаты
    if (createChatForm) {
        createChatForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(createChatForm);
            const response = await fetch('/messi/create_chat', {
                method: 'POST',
                body: formData
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                if (response.ok) {
                    alert(`Комната создана с ID: ${result.room_id}`);
                    // Перенаправление на страницу чатов с room_id
                    window.location.href = `/messi/?room_id=${result.room_id}`;
                } else {
                    alert(`Ошибка: ${result.error}`);
                }
            }
        });
    }

    // Обработка присоединения к комнате
    if (joinChatForm) {
        joinChatForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(joinChatForm);
            const response = await fetch('/messi/join_chat', {
                method: 'POST',
                body: formData
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                if (response.ok) {
                    alert(`Присоединились к комнате с ID: ${result.room_id}`);
                    // Перенаправление на страницу чатов с room_id
                    window.location.href = `/messi/?room_id=${result.room_id}`;
                } else {
                    alert(`Ошибка: ${result.error}`);
                }
            }
        });
    }
    
    // Обработка отправки сообщения через WebSocket
    if (sendMessageButton) {
        sendMessageButton.addEventListener('click', () => {
            const message = messageInput.value.trim();
            if (message && socket && socket.readyState === WebSocket.OPEN) {
                const msg = {
                    type: "chat",
                    content: message,
                    room_id: roomID
                };
                socket.send(JSON.stringify(msg));   //теперь отправка через json
                appendMessage("Вы", message);
                messageInput.value = '';
            }
        });
    }

    // Обработка выхода из системы
    if (logoutButton) {
        logoutButton.addEventListener('click', async () => {
            const response = await fetch('/logout', {
                method: 'POST'
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                if (response.ok) {
                    window.location.href = '/';
                } else {
                    alert('Ошибка при выходе из системы');
                }
            }
        });
    }

    // Обработка удаления комнаты
    if (deleteChatButton) {
        deleteChatButton.addEventListener('click', async () => {
            if (confirm('Вы уверены, что хотите удалить эту комнату? Это действие нельзя отменить.')) {
                const roomId = roomID; // roomID уже получен из URL
                if (!roomId) {
                    showNotification('Ошибка', 'Не указан идентификатор комнаты для удаления.', 'danger');
                    return;
                }
                try {
                    const response = await fetch(`/messi/chat?room_id=${encodeURIComponent(roomId)}`, {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });

                    const result = await response.json();
                    if (response.ok) {
                        showNotification('Успех', result.message, 'success');
                        window.location.href = '/messi/hub';
                    } else {
                        // Обработка ошибок, возвращаемых сервером
                        showNotification('Ошибка', result.error || 'Неизвестная ошибка', 'danger');
                    }
                } catch (error) {
                    console.error('Ошибка при удалении комнаты:', error);
                    showNotification('Ошибка', 'Произошла ошибка при удалении комнаты.', 'danger');
                }
            }
        });
    }

        // Функция для отображения уведомлений с помощью Bootstrap Toasts
    function showNotification(title, message, type = 'info') {
        const notificationContainer = document.getElementById('notification-container');

        const toastId = `toast-${Date.now()}`;
    
        const toastHTML = `
            <div class="toast" id="${toastId}" role="alert" aria-live="assertive" aria-atomic="true" data-delay="5000">
                <div class="toast-header bg-${type} text-white">
                    <strong class="mr-auto">${title}</strong>
                    <small class="text-muted">только что</small>
                    <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Закрыть">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
               <div class="toast-body">
                    ${message}
                </div>
            </div>
        `;
    
            notificationContainer.insertAdjacentHTML('beforeend', toastHTML);
            const toastElement = document.getElementById(toastId);
            $(toastElement).toast('show');
    
            // Удаляем уведомление из DOM после его скрытия
            toastElement.addEventListener('hidden.bs.toast', function () {
            toastElement.remove();
        });
    }
// Обработка загрузки файла
    if (fileUploadForm) {
        fileUploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!fileInput.files[0]) {
                showNotification('Ошибка', 'Файл не выбран', 'danger');
                return;
            }
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            console.log(`Отправляем файл в комнату: ${roomID}`);
            try {
                const response = await fetch(`/messi/chat/send-file?room_id=${encodeURIComponent(roomID)}`, {
                    method: 'POST',
                    body: formData,
                });

                const result = await response.json();
                if (response.ok) {
                    showNotification('Успех', result.message, 'success');
                    fileInput.value = ''; // Сбросить выбор файла
                    fetchFiles(); // Обновить список файлов
                } else {
                    console.error(`Ошибка загрузки файла: ${result.error}`);
                    showNotification('Ошибка', result.error || 'Неизвестная ошибка', 'danger');
                }
            } catch (error) {
                console.error('Ошибка при отправке файла:', error);
                showNotification('Ошибка', 'Ошибка отправки файла', 'danger');
            }
        });
    }   
    async function fetchFiles() {
        try {
            const response = await fetch(`/messi/chat/files?room_id=${encodeURIComponent(roomID)}`);
            if (response.ok) {
                const files = await response.json();
                const filesDiv = document.getElementById('files');
                filesDiv.innerHTML = ''; // Очистить текущий список
    
                if (files.length === 0) {
                    filesDiv.innerHTML = '<p>Нет файлов в этой комнате.</p>';
                    return;
                }
    
                files.forEach(file => {
                    const fileItem = document.createElement('div');
                    fileItem.className = 'file-item mb-2';
                    fileItem.innerHTML = `
                        <a href="/messi/chat/download-file?room_id=${encodeURIComponent(roomID)}&file_name=${encodeURIComponent(file.file_name)}" target="_blank">${escapeHtml(file.file_name)}</a>
                        <span class="text-muted" style="font-size: 0.8em;">(${file.file_size} байт)</span>
                    `;
                    filesDiv.appendChild(fileItem);
                });
            } else {
                console.error('Ошибка при получении списка файлов');
            }
        } catch (error) {
            console.error('Ошибка при получении списка файлов:', error);
        }
    }
    
    // Вызов fetchFiles при загрузке страницы или после добавления нового файла
    if (roomID) {
        connectWebSocket(roomID);
        fetchFiles();
    }

    // Функция подключения к WebSocket
    function connectWebSocket(roomID) {
        console.log("ПРИВЕТ СОЕДИНЕНИЕ WS");
        socket = new WebSocket(`ws://${window.location.host}/messi/ws?room_id=${roomID}`);

        socket.onopen = function(event) {
            console.log("WebSocket соединение установлено");
        };

        socket.onmessage = function(event) {
            console.log("ПРИВЕТ СОЕДИНЕНИЕ WS");
            const message = event.data;
            const data = JSON.parse(event.data);
            console.log(message);
            console.log(data);
            if (data.type === "error") {
                alert(`Ошибка: ${data.message}`);
            } else if (data.type === "chat_deleted") {
                showNotification('Чат удалён', 'Комната, в которой вы находитесь, была удалена.', 'warning');
                window.location.href = '/messi/hub'; // Перенаправление на лобби
            }
            appendMessage("Другой пользователь", message);
        };

        socket.onclose = function(event) {
            console.log("WebSocket соединение закрыто");
        };

        socket.onerror = function(error) {
            console.error("WebSocket ошибка:", error);
        };
    }

    // Функция добавления сообщения в раздел сообщений
    function appendMessage(sender, message) {
        const messageElement = document.createElement('p');
        messageElement.textContent = `${sender}: ${message}`;
        messagesDiv.appendChild(messageElement);
    }

});