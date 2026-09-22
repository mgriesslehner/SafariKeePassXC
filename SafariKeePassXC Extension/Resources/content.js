// Content script: detects login forms and fills in credentials from KeePassXC.
//
// Flow: find a visible password field (+ the username field preceding it),
// ask the background bridge for logins matching this page's URL (the
// background prefers the sender URL over anything we send), then fill the
// best match. KeePassXC returns entries best-match-first. TOTP fields
// (autocomplete="one-time-code" etc.) are filled from the entry's `totp`.

(() => {
    "use strict";

    let requestId = 0;
    const filledFields = new WeakSet();
    let knownEntries = null;

    // -- Helpers --

    function isVisible(element) {
        if (!element || element.disabled || element.readOnly) return false;
        const rect = element.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return false;
        const style = window.getComputedStyle(element);
        return style.visibility !== "hidden" && style.display !== "none";
    }

    function setValue(input, value) {
        input.focus();
        input.value = value;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
        input.blur();
    }

    function findUsernameField(passwordField, scope) {
        const candidates = [...scope.querySelectorAll(
            'input[type="text"], input[type="email"], input:not([type])'
        )].filter(isVisible);

        let usernameField = null;
        for (const candidate of candidates) {
            if (passwordField.compareDocumentPosition(candidate) & Node.DOCUMENT_POSITION_PRECEDING) {
                usernameField = candidate;
            }
        }
        return usernameField;
    }

    async function fetchLogins() {
        if (knownEntries !== null) return knownEntries;
        try {
            const response = await browser.runtime.sendMessage({
                id: ++requestId,
                action: "get-logins",
                url: window.location.href,
            });
            if (!response?.success) {
                console.debug("SafariKeePassXC: no credentials –", response?.error);
                return null;
            }
            knownEntries = response.result?.entries ?? [];
            return knownEntries;
        } catch {
            return null;
        }
    }

    // -- Credential autofill --

    function findLoginFields() {
        const passwordField = [...document.querySelectorAll('input[type="password"]')].find(isVisible);
        if (!passwordField) return null;
        const usernameField = findUsernameField(passwordField, passwordField.form ?? document);
        return { usernameField, passwordField };
    }

    async function attemptAutofill() {
        const fields = findLoginFields();
        if (!fields || filledFields.has(fields.passwordField)) return;
        if (fields.passwordField.value) return;

        const entries = await fetchLogins();
        if (!entries) return;

        const entry = entries.find((candidate) => !candidate.expired) ?? entries[0];
        if (!entry) return;

        if (fields.usernameField && !fields.usernameField.value) {
            setValue(fields.usernameField, entry.login);
        }
        setValue(fields.passwordField, entry.password);
        filledFields.add(fields.passwordField);
        console.debug(`SafariKeePassXC: filled credentials for "${entry.name}"`);
    }

    // -- TOTP autofill --

    function findTotpField() {
        const selector = 'input[autocomplete="one-time-code"], '
            + 'input[name*="otp" i], input[id*="otp" i], '
            + 'input[name*="2fa" i], input[id*="2fa" i]';
        return [...document.querySelectorAll(selector)]
            .filter((input) => input.type !== "password" && input.type !== "hidden")
            .find(isVisible);
    }

    async function attemptTotpFill() {
        const field = findTotpField();
        if (!field || filledFields.has(field) || field.value) return;

        const entries = await fetchLogins();
        const entry = (entries ?? []).find((candidate) => candidate.totp);
        if (!entry) return;

        setValue(field, entry.totp);
        filledFields.add(field);
        console.debug(`SafariKeePassXC: filled TOTP for "${entry.name}"`);
    }

    // -- Save / update on submit --

    function handleSubmit(event) {
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) return;

        const passwordField = [...form.querySelectorAll('input[type="password"]')].find(isVisible);
        if (!passwordField || !passwordField.value) return;

        const usernameField = findUsernameField(passwordField, form);
        const login = usernameField?.value ?? "";
        const password = passwordField.value;

        const entries = knownEntries ?? [];
        if (entries.some((entry) => entry.login === login && entry.password === password)) return;

        const existing = entries.find((entry) => entry.login === login);

        browser.runtime.sendMessage({
            id: ++requestId,
            action: "queue-save",
            url: window.location.href,
            login,
            password,
            uuid: existing?.uuid,
        }).then((response) => {
            if (response?.success) showSaveBanner(login, Boolean(existing));
        }).catch(() => {
            // Page is navigating away; the request already left the page.
        });
    }

    document.addEventListener("submit", handleSubmit, true);

    // -- Save banner --

    let bannerHost = null;

    function removeBanner() {
        bannerHost?.remove();
        bannerHost = null;
    }

    function dismissPendingSave() {
        browser.runtime.sendMessage({ id: ++requestId, action: "dismiss-pending-save" }).catch(() => {});
        removeBanner();
    }

    function showSaveBanner(login, isUpdate) {
        if (window.top !== window) return;
        removeBanner();

        const host = document.createElement("div");
        host.style.cssText = "all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647;";
        const shadow = host.attachShadow({ mode: "closed" });

        const style = document.createElement("style");
        style.textContent = `
            .banner {
                display: flex;
                align-items: center;
                gap: 10px;
                max-width: 420px;
                padding: 12px 14px;
                border-radius: 10px;
                background: #f5f5f7;
                color: #1d1d1f;
                box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
                font: 13px/1.4 -apple-system, sans-serif;
            }
            button {
                font: inherit;
                padding: 4px 10px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                white-space: nowrap;
            }
            .save { background: #0071e3; color: #fff; }
            .dismiss { background: rgba(0, 0, 0, 0.08); color: inherit; }
            @media (prefers-color-scheme: dark) {
                .banner { background: #2c2c2e; color: #f5f5f7; }
                .dismiss { background: rgba(255, 255, 255, 0.15); }
            }
        `;

        const text = document.createElement("span");
        text.textContent = browser.i18n.getMessage(
            isUpdate ? "save_banner_update" : "save_banner_new",
            [login || "?"]
        );

        const saveButton = document.createElement("button");
        saveButton.className = "save";
        saveButton.textContent = browser.i18n.getMessage(
            isUpdate ? "save_banner_button_update" : "save_banner_button_save"
        );
        saveButton.addEventListener("click", async () => {
            const response = await browser.runtime
                .sendMessage({ id: ++requestId, action: "confirm-pending-save" })
                .catch(() => null);
            if (response?.success) {
                removeBanner();
            } else {
                text.textContent = response?.error ?? "Error";
                saveButton.disabled = true;
                setTimeout(removeBanner, 5000);
            }
        });

        const dismissButton = document.createElement("button");
        dismissButton.className = "dismiss";
        dismissButton.textContent = browser.i18n.getMessage("save_banner_dismiss");
        dismissButton.addEventListener("click", dismissPendingSave);

        const banner = document.createElement("div");
        banner.className = "banner";
        banner.append(text, saveButton, dismissButton);
        shadow.append(style, banner);
        (document.body ?? document.documentElement).append(host);
        bannerHost = host;

        setTimeout(() => {
            if (bannerHost === host) dismissPendingSave();
        }, 60 * 1000);
    }

    async function checkPendingSave() {
        if (window.top !== window) return;
        try {
            const response = await browser.runtime.sendMessage({
                id: ++requestId,
                action: "get-pending-save",
                url: window.location.href,
            });
            const pending = response?.result;
            if (pending) showSaveBanner(pending.login, pending.isUpdate);
        } catch {
            // Extension context gone (e.g. during navigation).
        }
    }

    checkPendingSave();

    // -- Fill on demand (entry picker in the popup) --

    browser.runtime.onMessage.addListener((request) => {
        if (request?.action !== "fill-credentials") return;
        const fields = findLoginFields();
        if (!fields) return;
        if (fields.usernameField) {
            setValue(fields.usernameField, request.login ?? "");
        }
        setValue(fields.passwordField, request.password ?? "");
        filledFields.add(fields.passwordField);
        return Promise.resolve({ success: true });
    });

    console.debug("SafariKeePassXC: content script active on", window.location.href);

    function scan() {
        attemptAutofill();
        attemptTotpFill();
    }
    scan();

    let debounce = null;
    const observer = new MutationObserver(() => {
        clearTimeout(debounce);
        debounce = setTimeout(scan, 400);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
})();
