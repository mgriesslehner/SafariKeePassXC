//
//  ViewController.swift
//  SafariKeePassXC
//
//  Created by Markus Griesslehner on 29.07.26.
//

import Cocoa
import SafariServices
import WebKit

let extensionBundleIdentifier = "at.griesslehner.SafariKeePassXC.Extension"

class ViewController: NSViewController, WKNavigationDelegate, WKScriptMessageHandler {

    @IBOutlet var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        self.webView.navigationDelegate = self
        self.webView.configuration.userContentController.add(self, name: "controller")
        self.webView.loadFileURL(Bundle.main.url(forResource: "Main", withExtension: "html")!, allowingReadAccessTo: Bundle.main.resourceURL!)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: extensionBundleIdentifier) { (state, error) in
            guard let state = state, error == nil else {
                // Insert code to inform the user that something went wrong.
                return
            }

            DispatchQueue.main.async {
                if #available(macOS 13, *) {
                    webView.evaluateJavaScript("show(\(state.isEnabled), true)")
                } else {
                    webView.evaluateJavaScript("show(\(state.isEnabled), false)")
                }
            }
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? String,
                body == "open-preferences" else {
            return
        }

        SFSafariApplication.showPreferencesForExtension(
            withIdentifier: extensionBundleIdentifier
        ) { error in
            if let error {
                print("Could not open Safari Extension preferences:")
                print("   \(error)")
                print("   domain: \((error as NSError).domain)")
                print("   code: \((error as NSError).code)")
                print("   userInfo: \((error as NSError).userInfo)")
                return
            }

            DispatchQueue.main.async {
                if let window = self.view.window {
                    (NSApp.delegate as? AppDelegate)?.moveToMenuBar(window)
                }
            }
        }
    }

}
