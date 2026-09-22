// The host app page has no browser.i18n (that only exists in the extension),
// so localization is done with a small dictionary keyed by the system language.
// English is the default; German is provided as a second language.
// Values may contain markup and are applied via innerHTML - they are static,
// developer-controlled strings only.
const translations = {
    en: {
        state_unknown: "You can turn on the Safari extension in Safari Settings.",
        state_on: "The Safari extension is turned on.",
        state_off: "The Safari extension is still turned off.",
        open_preferences: "Open Safari Settings …",
        setup_heading: "Getting started",
        setup_step_keepassxc: "Install and start <strong>KeePassXC</strong>. In <em>Settings&nbsp;→ Browser Integration</em>, turn on <em>“Enable browser integration”</em>.",
        setup_step_unlock: "Unlock your database in KeePassXC.",
        setup_step_enable: "Turn on the extension in <em>Safari&nbsp;→ Settings&nbsp;→ Extensions</em> and allow website access.",
        setup_step_connect: "Click the extension icon in Safari and choose <em>“Connect to KeePassXC”</em>. Confirm and name the connection in KeePassXC.",
        setup_note: "Important: This app is the bridge between Safari and KeePassXC - it must stay open for the extension to work. The window may be closed.",
    },
    de: {
        state_unknown: "Die Safari-Erweiterung kann in den Safari-Einstellungen aktiviert werden.",
        state_on: "Die Safari-Erweiterung ist aktiviert.",
        state_off: "Die Safari-Erweiterung ist noch deaktiviert.",
        open_preferences: "Safari-Einstellungen öffnen …",
        setup_heading: "Erste Schritte",
        setup_step_keepassxc: "<strong>KeePassXC</strong> installieren und starten. Unter <em>Einstellungen&nbsp;→ Browser-Integration</em> die Option <em>„Browser-Integration aktivieren“</em> einschalten.",
        setup_step_unlock: "Die Datenbank in KeePassXC entsperren.",
        setup_step_enable: "Die Erweiterung in <em>Safari&nbsp;→ Einstellungen&nbsp;→ Erweiterungen</em> aktivieren und den Website-Zugriff erlauben.",
        setup_step_connect: "In Safari das Erweiterungs-Symbol anklicken und <em>„Mit KeePassXC verbinden“</em> wählen. Die Verbindung in KeePassXC bestätigen und benennen.",
        setup_note: "Wichtig: Diese App ist die Brücke zwischen Safari und KeePassXC - sie muss geöffnet bleiben, damit die Erweiterung funktioniert. Das Fenster darf geschlossen werden.",
    },
};

const language = (navigator.language ?? "en").toLowerCase().startsWith("de") ? "de" : "en";

function t(key) {
    return translations[language][key] ?? translations.en[key] ?? key;
}

function localizeDocument() {
    document.documentElement.lang = language;
    for (const element of document.querySelectorAll("[data-i18n]")) {
        element.innerHTML = t(element.dataset.i18n);
    }
}

function show(enabled, useSettingsInsteadOfPreferences) {
    if (typeof enabled === "boolean") {
        document.body.classList.toggle(`state-on`, enabled);
        document.body.classList.toggle(`state-off`, !enabled);
    } else {
        document.body.classList.remove(`state-on`);
        document.body.classList.remove(`state-off`);
    }
}

function openPreferences() {
    webkit.messageHandlers.controller.postMessage("open-preferences");
}

localizeDocument();
document.querySelector("button.open-preferences").addEventListener("click", openPreferences);
