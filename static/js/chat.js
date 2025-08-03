// static/js/chat.js

function refreshChat(taskId) {
    fetch(`/chat/${taskId}`)
        .then(res => res.text())
        .then(html => {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            const newMessages = doc.getElementById('chat-box').innerHTML;
            document.getElementById('chat-box').innerHTML = newMessages;
        });
}

function setupAutoRefresh(taskId) {
    setInterval(() => {
        refreshChat(taskId);
    }, 5000);
}
