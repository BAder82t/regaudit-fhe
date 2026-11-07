// The macOS launcher for the Evidence Verification Portal.
//
// It does four things and nothing else: it starts the portal that is bundled inside this application with the
// bundled Python, waits until the portal answers on 127.0.0.1, opens the default browser at it, and stops the
// portal when the application quits. It has no window and no network access of its own beyond asking the portal
// whether it is up. It does not read, write or keep any report, key or setting.
//
// Test options (never needed in normal use): `--no-browser` does not open the browser, `--print-url` prints
// `PORTAL_URL=<url>` once the portal answers, and everything after `--` is passed on to the portal's `serve`.
//
// Copyright (C) 2026 VaultBytes Innovations Ltd
// Licensed under AGPL-3.0-or-later.

import AppKit
import Foundation
import Darwin

let appName = "Evidence Verification Portal"

struct Options {
    var openBrowser = true
    var printURL = false
    var extra: [String] = []
}

func parseOptions() -> Options {
    var o = Options()
    var args = Array(CommandLine.arguments.dropFirst())
    while let a = args.first {
        args.removeFirst()
        switch a {
        case "--no-browser": o.openBrowser = false
        case "--print-url": o.printURL = true
        case "--": o.extra = args; args = []
        default: break  // macOS may add -psn_ and similar arguments; ignore them
        }
    }
    return o
}

/// A free port on 127.0.0.1, found by binding to port 0. There is a short gap before the portal binds it; the
/// portal refuses to start if it is taken and the launcher then reports that instead of waiting.
func freeLoopbackPort() -> UInt16? {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    if fd < 0 { return nil }
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = 0
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let bound = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    if bound != 0 { return nil }
    var out = sockaddr_in()
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    let got = withUnsafeMutablePointer(to: &out) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
    }
    if got != 0 { return nil }
    return UInt16(bigEndian: out.sin_port)
}

final class OutputTail {
    private let lock = NSLock()
    private var data = Data()
    func append(_ chunk: Data) {
        lock.lock(); defer { lock.unlock() }
        data.append(chunk)
        if data.count > 8192 { data = data.suffix(8192) }
    }
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    let options = parseOptions()
    var process: Process?
    var url: URL?
    var quitting = false
    let tail = OutputTail()
    var signalSources: [DispatchSourceSignal] = []
    var inputPipe: Pipe?  // the portal stops by itself when this closes, which it does if this program is killed

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        // A `kill`, a logout or the system stopping the application takes the same path as Quit, so the portal
        // is stopped cleanly. (SIGKILL cannot be handled: the portal would then keep running until stopped.)
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler { NSApp.terminate(nil) }
            source.resume()
            signalSources.append(source)
        }
        guard let resources = Bundle.main.resourcePath else { return fail("The application is damaged (no resources folder). Copy the application from the disk image again.") }
        let python = resources + "/python/bin/python3"
        guard FileManager.default.isExecutableFile(atPath: python) else {
            return fail("The application is damaged: the bundled Python is missing. Copy the application from the disk image again.")
        }
        guard let port = freeLoopbackPort() else { return fail("Could not find a free local port.") }
        let target = URL(string: "http://127.0.0.1:\(port)/")!
        url = target

        let p = Process()
        p.executableURL = URL(fileURLWithPath: python)
        // -I: ignore PYTHON* variables and the user site, and do not put the working directory on the path.
        // -B: write no bytecode. The portal compiles its own package before it redirects the bytecode cache, and
        // anything written inside the bundle would break its signature.
        p.arguments =
            ["-I", "-B", "-m", "regaudit_portal", "serve", "--port", String(port), "--exit-when-input-closes"]
            + options.extra
        let env = ProcessInfo.processInfo.environment
        var childEnv: [String: String] = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": env["LANG"] ?? "en_US.UTF-8"]
        for key in ["HOME", "USER", "TMPDIR"] { if let v = env[key] { childEnv[key] = v } }
        p.environment = childEnv
        let input = Pipe()
        inputPipe = input
        p.standardInput = input
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [tail] handle in
            let chunk = handle.availableData
            if chunk.isEmpty { handle.readabilityHandler = nil } else { tail.append(chunk) }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async { self?.portalExited(status: proc.terminationStatus) }
        }
        do { try p.run() } catch { return fail("Could not start the portal: \(error.localizedDescription)") }
        process = p
        waitUntilUp(target)
    }

    /// Ask the portal for its status until it answers, then open the browser. Any HTTP answer, including the
    /// "Verification unavailable" page's 503, means the portal is up and the browser should show what it says.
    func waitUntilUp(_ target: URL) {
        let statusURL = target.appendingPathComponent("api/status")
        DispatchQueue.global().async { [weak self] in
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 2
            config.connectionProxyDictionary = [:]  // never through a proxy
            let session = URLSession(configuration: config)
            let deadline = Date().addingTimeInterval(45)
            while Date() < deadline {
                if self?.quitting == true || self?.process?.isRunning == false { return }
                let sem = DispatchSemaphore(value: 0)
                var up = false
                session.dataTask(with: statusURL) { _, response, _ in
                    if response is HTTPURLResponse { up = true }
                    sem.signal()
                }.resume()
                _ = sem.wait(timeout: .now() + 3)
                if up {
                    DispatchQueue.main.async { self?.ready(target) }
                    return
                }
                Thread.sleep(forTimeInterval: 0.25)
            }
            DispatchQueue.main.async { self?.fail("The portal did not start within 45 seconds.\n\n\(self?.tail.text ?? "")") }
        }
    }

    func ready(_ target: URL) {
        if options.printURL { print("PORTAL_URL=\(target.absoluteString)"); fflush(stdout) }
        if options.openBrowser { NSWorkspace.shared.open(target) }
    }

    func portalExited(status: Int32) {
        if quitting { return }
        let detail = tail.text.trimmingCharacters(in: .whitespacesAndNewlines)
        fail("The portal stopped (exit code \(status)).\n\n\(detail.suffix(1200))")
    }

    func fail(_ message: String) {
        if options.printURL { FileHandle.standardError.write(Data("LAUNCHER_ERROR=\(message)\n".utf8)) }
        if !options.openBrowser {  // test mode: no dialogs, just stop
            quitting = true
            process?.terminate()
            exit(1)
        }
        let alert = NSAlert()
        alert.messageText = appName
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Quit")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        quitting = true
        process?.terminate()
        NSApp.terminate(nil)
    }

    @objc func openPortal() { if let u = url { NSWorkspace.shared.open(u) } }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openPortal()
        return false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        quitting = true
        guard let p = process, p.isRunning else { return .terminateNow }
        p.terminate()  // SIGTERM: the portal stops cleanly and removes its private bytecode folder
        // Wait here, on the main thread, for up to six seconds. The application is quitting and has no window, and a
        // deferred terminate would need the main queue, which is not serviced while AppKit waits for it.
        let end = Date().addingTimeInterval(6)
        while p.isRunning && Date() < end { Thread.sleep(forTimeInterval: 0.05) }
        if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        return .terminateNow
    }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let menu = NSMenu()
        menu.addItem(withTitle: "Open the portal in your browser", action: #selector(openPortal), keyEquivalent: "o").target = self
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit \(appName)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = menu
        NSApp.mainMenu = main
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
