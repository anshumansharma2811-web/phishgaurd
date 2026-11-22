
const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const scanResult = document.getElementById("scanResult");
const resultTitle = document.getElementById("resultTitle");
const resultDescription = document.getElementById("resultDescription");
const resultBadge = document.getElementById("resultBadge");
let scanTimeout = null;
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
    scanResult.classList.add("result-error");

    resultTitle.textContent = "Invalid URL";
    resultDescription.textContent =
        "Please enter a valid URL starting with https:// or http://";

    // Clear metrics from any previous successful preview.
    document.getElementById("formatStatus").textContent = "Invalid";
    document.getElementById("protocolStatus").textContent = "Unknown";

    return;
}


    scanButton.disabled = true;
    scanButton.replaceChildren();

const spinner = document.createElement("span");
spinner.className = "loading-spinner";
spinner.setAttribute("aria-hidden", "true");

const loadingText = document.createElement("span");
loadingText.textContent = "Preparing...";

scanButton.append(spinner, loadingText);
scanButton.setAttribute("aria-busy", "true");

    // Demonstration only: no network request or ML prediction.
    
    scanTimeout = setTimeout(() => {
        scanTimeout = null;
       scanResult.hidden = false;
scanResult.classList.remove("result-error");
resultBadge.textContent = "INPUT ERROR";
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
        scanButton.removeAttribute("aria-busy");

        scanResult.scrollIntoView({
            behavior: "smooth",
            block: "nearest"
        });
    }, 600);
});

/* ===== SESSION SCAN HISTORY ===== */

const historyList = document.getElementById("historyList");
const historySearch = document.getElementById("historySearch");
const historyCounter = document.getElementById("historyCounter");
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
    const totalSaved = getHistory().length;

historyCounter.textContent = `${totalSaved} / 10`;
    
const history = getHistory();
const searchTerm = historySearch.value.trim().toLowerCase();

const filteredHistory = history
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) =>
        entry.url.toLowerCase().includes(searchTerm)
    );

historyList.replaceChildren();

   
if (filteredHistory.length === 0) {
    const empty = document.createElement("p");
    empty.className = "history-empty";

    empty.textContent = history.length === 0
        ? "No URLs previewed yet."
        : "No matching URLs found.";

    historyList.appendChild(empty);
    return;
}


    filteredHistory.forEach(({ entry, index }) => {
        const item = document.createElement("div");
        item.className = "history-item";

        const urlText = document.createElement("span");
        urlText.className = "history-url";
        urlText.textContent = entry.url;
        urlText.title = entry.url;

        const timeText = document.createElement("span");
        timeText.className = "history-time";
        timeText.textContent = entry.time;

       
const deleteButton = document.createElement("button");
deleteButton.type = "button";
deleteButton.className = "history-delete";
deleteButton.textContent = "Delete";
deleteButton.title = "Remove this URL from history";

deleteButton.addEventListener("click", (event) => {
    // Prevent the history item's click handler from running.
    event.stopPropagation();

    const updatedHistory = getHistory();
    updatedHistory.splice(index, 1);

    sessionStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(updatedHistory)
    );

   /* ===== LIVE HISTORY SEARCH ===== */

historySearch.addEventListener("input", () => {
    renderHistory();
});
 renderHistory();
});

item.append(urlText, timeText, deleteButton);
historyList.appendChild(item);


item.title = "Click to reuse this URL";
item.style.cursor = "pointer";

item.addEventListener("click", () => {
    urlInput.value = entry.url;

    document.getElementById("scanner").scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

    urlInput.focus();
});

    });
}

clearHistoryButton.addEventListener("click", () => {
    sessionStorage.removeItem(HISTORY_KEY);
    renderHistory();
});

/* ===== LIVE HISTORY SEARCH ===== */

historySearch.addEventListener("input", () => {
    renderHistory();
});


renderHistory();

/* ===== ACTIVE NAVIGATION ===== */

const navLinks = document.querySelectorAll(".nav-links a");
const sections = document.querySelectorAll(
    "#home, #scanner, #features"
);

function updateActiveNavigation() {
    let currentSection = "home";

    sections.forEach((section) => {
        const sectionTop = section.getBoundingClientRect().top;

        if (sectionTop <= 160) {
            currentSection = section.id;
        }
    });

    navLinks.forEach((link) => {
        const target = link.getAttribute("href");

        link.classList.toggle(
            "active",
            target === `#${currentSection}`
        );
    });
}

window.addEventListener("scroll", updateActiveNavigation, {
    passive: true
});

window.addEventListener("load", updateActiveNavigation);

/* ===== RESET SCANNER ===== */

const resetButton = document.getElementById("resetButton");


resetButton.addEventListener("click", () => {
    // Cancel any pending scanner preview.
    if (scanTimeout !== null) {
        clearTimeout(scanTimeout);
        scanTimeout = null;
    }

    // Restore the scanner button.
    scanButton.disabled = false;
    scanButton.textContent = "Scan URL";
    scanButton.removeAttribute("aria-busy");

    // Clear the input and previous result.
    urlInput.value = "";
    scanResult.hidden = true;
    scanResult.classList.remove("result-error");
    resultBadge.textContent = "PREVIEW ONLY";

    urlInput.focus();
});

