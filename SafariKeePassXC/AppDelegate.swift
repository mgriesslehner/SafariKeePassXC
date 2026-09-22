//
//  AppDelegate.swift
//  SafariKeePassXC
//
//  Created by Markus Griesslehner on 29.07.26.
//

import Cocoa

@main
class AppDelegate: NSObject, NSApplicationDelegate {

    private let bridgeServer = BridgeServer()
    private var statusItem: NSStatusItem?
    private weak var mainWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task {
            await bridgeServer.start()
        }
    }

    // MARK: - Menu bar mode

    func moveToMenuBar(_ window: NSWindow) {
        mainWindow = window

        window.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
        showStatusItem()
    }

    private func showStatusItem() {
        guard statusItem == nil else { return }

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "key.circle", accessibilityDescription: "SafariKeePassXC")
        item.button?.target = self
        item.button?.action = #selector(restoreFromMenuBar)
        statusItem = item
    }

    @objc private func restoreFromMenuBar() {
        if let statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
            self.statusItem = nil
        }

        NSApp.setActivationPolicy(.regular)
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        mainWindow?.makeKeyAndOrderFront(nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        Task {
            await bridgeServer.stop()
        }
    }
}

class MainWindow: NSWindow {

    override func miniaturize(_ sender: Any?) {
        (NSApp.delegate as? AppDelegate)?.moveToMenuBar(self)
    }

}
