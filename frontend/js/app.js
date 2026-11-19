
const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const scanResult = document.getElementById("scanResult");
const resultTitle = document.getElementById("resultTitle");
const resultDescription = document.getElementById("resultDescription");

scanForm.addEventListener("submit", (event) => {
    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        urlInput.focus();
        return;
    }

    let parsedURL;

    try {
        parsedURL = new URL(url);

        if (!["http:", "https:"].includes(parsedURL.protocol)) {
            throw new Error("Unsupported URL protocol");
        }

        if (!parsedURL.hostname.includes(".")) {
            throw new Error("Invalid hostname");
        }
    } catch (error) {
        scanResult.hidden = false;
        resultTitle.textContent = "Invalid URL";
        resultDescription.textContent =
            "Please enter a valid HTTP or HTTPS URL.";
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Preparing preview...";

    // Demonstration only: no network request or ML prediction.
    setTimeout(() => {
        scanResult.hidden = false;
        saveHistory(parsedURL.href);
        document.getElementById("formatStatus").textContent = "Valid";

document.getElementById("protocolStatus").textContent =
    parsedURL.protocol === "https:" ? "HTTPS" : "HTTP";

        resultTitle.textContent = "URL Preview Ready";

        resultDescription.textContent =
            `Target: ${parsedURL.href}\n` +
            `Hostname: ${parsedURL.hostname}\n` +
            `Protocol: ${parsedURL.protocol.replace(":", "").toUpperCase()}\n\n` +
            "Demo mode: No phishing classification has been performed.";

        resultDescription.style.whiteSpace = "pre-line";

        scanButton.disabled = false;
        scanButton.textContent = "Scan URL";

        scanResult.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });
    }, 600);
});

/* ===== SESSION SCAN HISTORY ===== */

const historyList = document.getElementById("historyList");
const clearHistoryButton = document.getElementById("clearHistory");

const HISTORY_KEY = "phishguard_preview_history";

function getHistory() {
    try {
        return JSON.parse(sessionStorage.getItem(HISTORY_KEY)) || [];
    } catch {
        return [];
    }
}

function saveHistory(url) {
    const history = getHistory();

    history.unshift({
        url: url,
        time: new Date().toLocaleString()
    });

    sessionStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history.slice(0, 10))
    );

    renderHistory();
}

function renderHistory() {
    const history = getHistory();

    historyList.replaceChildren();

    if (history.length === 0) {
        const empty = document.createElement("p");
        empty.className = "history-empty";
        empty.textContent = "No URLs previewed yet.";
        historyList.appendChild(empty);
        return;
    }

    history.forEach((entry) => {
        const item = document.createElement("div");
        item.className = "history-item";

        const urlText = document.createElement("span");
        urlText.className = "history-url";
        urlText.textContent = entry.url;

        const timeText = document.createElement("span");
        timeText.className = "history-time";
        timeText.textContent = entry.time;

        item.append(urlText, timeText);
        historyList.appendChild(item);
    });
}

clearHistoryButton.addEventListener("click", () => {
    sessionStorage.removeItem(HISTORY_KEY);
    renderHistory();
});

renderHistory();
