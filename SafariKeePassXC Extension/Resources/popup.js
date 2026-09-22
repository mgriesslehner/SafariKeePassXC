// Popup UI.
//
// On open: fetch the KeePassXC status and - when connected and associated -
// the entries matching the active tab. Entries are shown as a clickable list;
// a click fills the login form in the page (via the content script).
// Passwords are never rendered here.

let requestId = 0;

const statusView = document.getElementById("status");
const entriesSection = document.getElementById("entries-section");
const entriesList = document.getElementById("entries");
const resultView = document.getElementById("result");
const associateButton = document.getElementById("associate");
const groupSection = document.getElementById("group-section");
const groupSelect = document.getElementById("save-group");

function api(message) {
    return browser.runtime.sendMessage({ id: ++requestId, ...message });
}

function t(key, substitutions) {
    return browser.i18n.getMessage(key, substitutions) || key;
}

function localizeDocument() {
    for (const element of document.querySelectorAll("[data-i18n]")) {
        element.textContent = t(element.dataset.i18n);
    }
}

async function activeTab() {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    return tabs[0];
}

function friendlyError(error) {
    const text = (error ?? "").toLowerCase();
    if (text.includes("host_app_not_running")) {
        return t("error_host_app_not_running");
    }
    if (text.includes("keepassxc_not_reachable")) {
        return t("error_keepassxc_not_reachable");
    }
    if (text.includes("database not opened") || text.includes("database is not opened")) {
        return t("error_database_locked");
    }
    if (text.includes("not_associated")) {
        return t("error_not_associated");
    }
    return t("error_generic", [error ?? t("error_unknown")]);
}

function isNoLoginsFound(error) {
    return (error ?? "").toLowerCase().includes("keepassxc_error 15");
}

function showResult(text) {
    resultView.hidden = false;
    resultView.textContent = text;
}

// -- Entries --

function renderEntries(entries) {
    entriesList.replaceChildren();
    entriesSection.hidden = !entries.length;
    if (!entries.length) return;

    for (const entry of entries) {
        const item = document.createElement("li");
        const button = document.createElement("button");
        button.className = "entry";
        button.title = t("entry_fill_tooltip");

        const name = document.createElement("span");
        name.className = "entry-name";
        name.textContent = entry.name || entry.login;

        const login = document.createElement("span");
        login.className = "entry-login";
        login.textContent = entry.login;

        button.append(name, login);
        button.addEventListener("click", () => fill(entry));
        item.append(button);
        entriesList.append(item);
    }
}

async function fill(entry) {
    try {
        const tab = await activeTab();
        await browser.tabs.sendMessage(tab.id, {
            action: "fill-credentials",
            login: entry.login,
            password: entry.password,
        });
        window.close();
    } catch {
        showResult(t("fill_no_form"));
    }
}

async function loadEntries() {
    const tab = await activeTab();
    if (!tab?.url?.startsWith("http")) return;

    const response = await api({ action: "get-logins", url: tab.url });
    if (!response?.success) {
        if (isNoLoginsFound(response?.error)) {
            renderEntries([]);
        } else {
            showResult(friendlyError(response?.error));
        }
        return;
    }
    renderEntries(response.result?.entries ?? []);
}

// -- Save group choice --

async function loadGroups() {
    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = t("save_group_default");
    groupSelect.replaceChildren(defaultOption);
    groupSection.hidden = false;

    try {
        const response = await api({ action: "get-database-groups" });
        if (!response?.success) return;

        const groups = response.result?.groups ?? [];
        const stored = await browser.storage.local.get("saveGroup");
        const selectedUuid = stored.saveGroup?.uuid;

        for (const group of groups) {
            const option = document.createElement("option");
            option.value = group.uuid;
            option.textContent = group.name;
            option.selected = group.uuid === selectedUuid;
            groupSelect.append(option);
        }
    } catch {
        // Section already visible with the default option as fallback.
    }
}

async function saveGroupChoice() {
    const option = groupSelect.selectedOptions[0];
    if (option?.value) {
        await browser.storage.local.set({
            saveGroup: { uuid: option.value, name: option.textContent },
        });
    } else {
        await browser.storage.local.remove("saveGroup");
    }
}

// -- Actions --

async function associate() {
    statusView.textContent = t("status_associating");
    const response = await api({ action: "associate" });
    if (!response?.success) {
        statusView.textContent = friendlyError(response?.error);
        return;
    }
    await init();
}

async function generatePassword() {
    const response = await api({ action: "generate-password" });
    if (!response?.success) {
        showResult(friendlyError(response?.error));
        return;
    }
    const password = response.result?.password ?? "";
    try {
        await navigator.clipboard.writeText(password);
        showResult(password + "\n\n" + t("copied_to_clipboard"));
    } catch {
        showResult(password);
    }
}

async function copyTotp() {
    const tab = await activeTab();
    if (!tab?.url?.startsWith("http")) {
        showResult(t("totp_no_website"));
        return;
    }
    const response = await api({ action: "get-logins", url: tab.url });
    if (!response?.success) {
        showResult(isNoLoginsFound(response?.error)
            ? t("totp_no_entry")
            : friendlyError(response?.error));
        return;
    }
    const entry = (response.result?.entries ?? []).find((candidate) => candidate.totp);
    if (!entry) {
        showResult(t("totp_no_entry"));
        return;
    }
    try {
        await navigator.clipboard.writeText(entry.totp);
        showResult(`${entry.name}: ${entry.totp}\n\n` + t("copied_to_clipboard"));
    } catch {
        showResult(`${entry.name}: ${entry.totp}`);
    }
}

// -- Startup --

async function loadVersion() {
    try {
        const response = await api({ action: "get-version" });
        const result = response?.result;
        if (!response?.success || !result?.version) return;
        document.getElementById("version").textContent =
            `v${result.version} (${result.build}) · `;
    } catch {
        // Footer simply stays without a version.
    }
}

async function init() {
    resultView.hidden = true;
    associateButton.hidden = true;
    entriesSection.hidden = true;
    groupSection.hidden = true;

    let status;
    try {
        status = await api({ action: "status" });
    } catch (error) {
        statusView.textContent = t("error_generic", [String(error)]);
        return;
    }

    if (!status?.success) {
        statusView.textContent = friendlyError(status?.error);
        return;
    }

    const result = status.result ?? {};
    if (!result.connected) {
        statusView.textContent = friendlyError(result.error ?? "keepassxc_not_reachable");
        return;
    }
    if (result.error) {
        statusView.textContent = friendlyError(result.error);
        return;
    }
    if (!result.associated) {
        statusView.textContent = t("status_not_associated", [result.keePassXCVersion ?? ""]);
        associateButton.hidden = false;
        return;
    }

    statusView.textContent = t("status_connected", [result.keePassXCVersion ?? ""]);
    await loadEntries();
    await loadGroups();
}

localizeDocument();
associateButton.addEventListener("click", associate);
groupSelect.addEventListener("change", saveGroupChoice);
document.getElementById("generate").addEventListener("click", generatePassword);
document.getElementById("totp").addEventListener("click", copyTotp);

loadVersion();
init();
