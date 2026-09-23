// Background script: the single bridge between the extension's JS contexts
// (popup, content scripts) and the native macOS app.
//
// Popup and content scripts send JSON requests via browser.runtime.sendMessage.
// Here we forward them to the native app (Swift), which talks to KeePassXC, and
// relay the JSON response straight back to the caller.
//
// The application identifier is required by the API signature; on Safari the
// message is always delivered to this extension's native handler.

const NATIVE_APP_ID = "at.griesslehner.SafariKeePassXC";

// -- Pending saves (save banner) --

const pendingSaves = new Map();
const PENDING_SAVE_TTL = 60 * 1000;

function pendingSaveFor(tabId, url) {
    const pending = pendingSaves.get(tabId);
    if (!pending) return null;

    let sameHost = false;
    try {
        sameHost = new URL(pending.url).hostname === new URL(url).hostname;
    } catch {
        // Leave sameHost false for unparsable URLs.
    }
    if (!sameHost || Date.now() - pending.queuedAt > PENDING_SAVE_TTL) {
        pendingSaves.delete(tabId);
        return null;
    }
    return pending;
}

browser.runtime.onMessage.addListener((request, sender) => {
    const message = { ...request };
    const tabId = sender.tab?.id;

    switch (message.action) {
        case "queue-save": {
            if (tabId === undefined) {
                return Promise.resolve({ success: false, error: "no_tab" });
            }
            pendingSaves.set(tabId, {
                url: sender.url ?? message.url,
                login: message.login,
                password: message.password,
                uuid: message.uuid,
                queuedAt: Date.now(),
            });
            return Promise.resolve({ success: true, result: {} });
        }

        // The banner only ever learns the login name, never the password.
        case "get-pending-save": {
            const pending = tabId === undefined
                ? null
                : pendingSaveFor(tabId, sender.url ?? message.url ?? "");
            return Promise.resolve({
                success: true,
                result: pending
                    ? { login: pending.login, isUpdate: Boolean(pending.uuid) }
                    : null,
            });
        }

        case "confirm-pending-save": {
            const pending = tabId === undefined ? null : pendingSaves.get(tabId);
            if (!pending) {
                return Promise.resolve({ success: false, error: "nothing_pending" });
            }
            pendingSaves.delete(tabId);
            return browser.storage.local.get("saveGroup").then(({ saveGroup }) =>
                browser.runtime.sendNativeMessage(NATIVE_APP_ID, {
                    id: message.id,
                    action: "set-login",
                    url: pending.url,
                    login: pending.login,
                    password: pending.password,
                    uuid: pending.uuid,
                    ...(saveGroup ? { group: saveGroup.name, groupUuid: saveGroup.uuid } : {}),
                }));
        }

        case "dismiss-pending-save": {
            if (tabId !== undefined) pendingSaves.delete(tabId);
            return Promise.resolve({ success: true, result: {} });
        }
    }

    // -- Native forwarding --
    
    // set-login is the only write action in the bridge API. It must only be
    // reachable through confirm-pending-save (which enforces the save banner,
    // host check, and TTL above); it is never forwarded here as-is.
    if (message.action === "set-login") {
        return Promise.resolve({ success: false, error: "forbidden_action" });
    }

    const urlBoundActions = ["get-logins"];
    if (urlBoundActions.includes(message.action) && sender.tab && sender.url) {
        message.url = sender.url;
    }

    return browser.runtime.sendNativeMessage(NATIVE_APP_ID, message);
});
