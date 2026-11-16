// The macOS launcher for the Evidence Verification Portal.
//
// It starts the portal that is bundled inside this application with the bundled Python, waits until the portal
// answers on 127.0.0.1, opens the default browser at it, and stops the portal when the application quits. It has no
// window and no network access of its own beyond asking the portal whether it is up. It does not read, write or keep
// any report, key or setting.
//
// Its menu also has "Administrator setup…". That opens a native file chooser for a setup plan, asks the bundled
// Python (`regaudit-portal admin-describe`) what the plan would do, shows that in a native alert with one empty field
// per issuer for the fingerprint the administrator received from that issuer, and passes what was typed to
// `regaudit-portal admin-apply`, which refuses unless every fingerprint matches. Then it restarts the portal so the
// new configuration is read. This code makes no trust decision of its own: it shows what Python says and passes on
// what was typed. Web content cannot reach a native menu, file chooser or alert.
//
// Test options (never needed in normal use): `--no-browser` does not open the browser, `--print-url` prints
// `PORTAL_URL=<url>` once the portal answers, and everything after `--` is passed on to the portal's `serve`.
//
// Copyright (C) 2026 VaultBytes Innovations Ltd
// Licensed under AGPL-3.0-or-later.

import AppKit
import Foundation
import Darwin
import UniformTypeIdentifiers

let appName = "Evidence Verification Portal"

/// The status `serve` ends with when another portal already holds the instance lock (sysexits EX_TEMPFAIL).
let alreadyRunningStatus: Int32 = 75

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

/// What a run of an administrator command printed, and how it ended.
struct ToolResult {
    let status: Int32
    let output: String
    let problems: String
}

final class Collected {
    private let lock = NSLock()
    private var data = Data()
    func set(_ chunk: Data) { lock.lock(); data = chunk; lock.unlock() }
    var text: String { lock.lock(); defer { lock.unlock() }; return String(decoding: data, as: UTF8.self) }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    let options = parseOptions()
    var process: Process?
    var url: URL?
    var quitting = false
    let tail = OutputTail()
    var signalSources: [DispatchSourceSignal] = []
    var inputPipe: Pipe?  // the portal stops by itself when this closes, which it does if this program is killed
    var python: String?
    var adminBusy = false
    var retiring: Process?  // a portal being stopped on purpose so that a new one reads the new configuration

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
        let bundled = resources + "/python/bin/python3"
        guard FileManager.default.isExecutableFile(atPath: bundled) else {
            return fail("The application is damaged: the bundled Python is missing. Copy the application from the disk image again.")
        }
        python = bundled
        startPortal()
    }

    /// The few variables a child process gets: a fixed search path, the language, and who and where the account is.
    func childEnvironment() -> [String: String] {
        let env = ProcessInfo.processInfo.environment
        var childEnv: [String: String] = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": env["LANG"] ?? "en_US.UTF-8"]
        for key in ["HOME", "USER", "TMPDIR"] { if let v = env[key] { childEnv[key] = v } }
        return childEnv
    }

    /// ``replacing`` is true when a portal of this application has just been stopped on purpose: the new one then waits a few
    /// seconds for the old one to release the instance lock instead of reporting that one is running.
    func startPortal(replacing: Bool = false) {
        guard !quitting, let python = python else { return }
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
            + (replacing ? ["--wait-for-instance", "8"] : [])
            + options.extra
        p.environment = childEnvironment()
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
            DispatchQueue.main.async { self?.portalExited(proc, status: proc.terminationStatus) }
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

    func portalExited(_ proc: Process, status: Int32) {
        if quitting || proc === retiring || proc !== process { return }  // stopped on purpose for a restart
        let detail = tail.text.trimmingCharacters(in: .whitespacesAndNewlines)
        if status == alreadyRunningStatus { return alreadyRunning(detail) }
        fail("The portal stopped (exit code \(status)).\n\n\(detail.suffix(1200))")
    }

    /// Another portal holds the instance lock for this account and configuration folder. Nothing is stopped: the running
    /// one is left alone, and this application says so, offers to open it, and quits.
    func alreadyRunning(_ detail: String) {
        var existing: URL?
        if let found = detail.range(of: "http://127\\.0\\.0\\.1:[0-9]+/", options: .regularExpression) {
            existing = URL(string: String(detail[found]))
        }
        let message = "The \(appName) is already running for this account. A second copy would use the same configuration folder at the same time, so this one did not start. The running one was not changed."
        if !options.openBrowser {  // test mode: no dialog
            FileHandle.standardError.write(Data("LAUNCHER_ERROR=ALREADY_RUNNING \(existing?.absoluteString ?? "")\n".utf8))
            quitting = true
            exit(alreadyRunningStatus)
        }
        let alert = NSAlert()
        alert.messageText = "\(appName) is already running"
        alert.informativeText = message
        alert.alertStyle = .informational
        if existing != nil { alert.addButton(withTitle: "Open it") }
        alert.addButton(withTitle: "Quit")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn, let target = existing { NSWorkspace.shared.open(target) }
        quitting = true
        NSApp.terminate(nil)
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

    // MARK: Administrator setup

    /// Run `regaudit-portal` with these arguments in the bundled Python, with no standard input, and hand back what it
    /// printed. It runs off the main thread, so the menu stays responsive, and the answer comes back on the main thread.
    func runTool(_ arguments: [String], then: @escaping (ToolResult) -> Void) {
        guard let python = python else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: python)
        p.arguments = ["-I", "-B", "-m", "regaudit_portal"] + arguments
        p.environment = childEnvironment()
        p.standardInput = FileHandle.nullDevice
        let out = Pipe()
        let err = Pipe()
        p.standardOutput = out
        p.standardError = err
        DispatchQueue.global().async {
            do { try p.run() } catch {
                let failed = ToolResult(status: -1, output: "", problems: "The setup command could not be started: \(error.localizedDescription)")
                DispatchQueue.main.async { then(failed) }
                return
            }
            let said = Collected()
            let problems = Collected()
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global().async { said.set(out.fileHandleForReading.readDataToEndOfFile()); group.leave() }
            group.enter()
            DispatchQueue.global().async { problems.set(err.fileHandleForReading.readDataToEndOfFile()); group.leave() }
            if group.wait(timeout: .now() + 120) == .timedOut {
                p.terminate()
                if group.wait(timeout: .now() + 10) == .timedOut { kill(p.processIdentifier, SIGKILL) }
                group.wait()
            }
            p.waitUntilExit()
            let result = ToolResult(status: p.terminationStatus, output: said.text, problems: problems.text)
            DispatchQueue.main.async { then(result) }
        }
    }

    /// Text that can be read, scrolled and copied in a box of fixed size, so a long text never pushes an alert's
    /// buttons off the screen. It shows the text exactly as given.
    func scrollingText(_ string: String, width: CGFloat, height: CGFloat) -> NSScrollView {
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: width, height: height))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let inside = scroll.contentSize
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: inside.width, height: inside.height))
        text.minSize = NSSize(width: 0, height: inside.height)
        text.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.autoresizingMask = [.width]
        text.textContainer?.containerSize = NSSize(width: inside.width, height: CGFloat.greatestFiniteMagnitude)
        text.textContainer?.widthTracksTextView = true
        text.isEditable = false
        text.isSelectable = true
        text.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        text.string = string.trimmingCharacters(in: .whitespacesAndNewlines)
        scroll.documentView = text
        return scroll
    }

    /// The same box, sized by constraints, for use inside a stack of views.
    func fixedBox(_ view: NSView, width: CGFloat, height: CGFloat) -> NSView {
        view.translatesAutoresizingMaskIntoConstraints = false
        view.widthAnchor.constraint(equalToConstant: width).isActive = true
        view.heightAnchor.constraint(equalToConstant: height).isActive = true
        return view
    }

    /// A native alert whose long text can be scrolled and copied.
    func inform(_ title: String, _ detail: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.accessoryView = scrollingText(detail, width: 520, height: 260)
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    @objc func administratorSetup() {
        if adminBusy || python == nil { return }
        let panel = NSOpenPanel()
        panel.title = "Choose a setup plan"
        panel.message = "Choose the setup plan you saved from the portal's Prepare a setup plan page."
        panel.prompt = "Choose"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json]
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let plan = panel.url else { return }
        adminBusy = true
        runTool(["admin-describe", "--json", "--", plan.path]) { [weak self] described in
            self?.askForFingerprints(described, plan: plan)
        }
    }

    /// Show what Python said about the plan, with one empty field per issuer. Nothing here checks what is typed:
    /// `admin-apply` does, and it refuses unless every fingerprint matches the key in the plan.
    func askForFingerprints(_ described: ToolResult, plan: URL) {
        guard let data = described.output.data(using: .utf8),
              let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            adminBusy = false
            return inform("The setup plan could not be read.", described.problems.isEmpty ? described.output : described.problems)
        }
        guard body["ok"] as? Bool == true,
              let summary = body["summary"] as? String,
              let digest = body["plan_sha256"] as? String,
              let issuers = body["issuers"] as? [[String: Any]], !issuers.isEmpty else {
            adminBusy = false
            return inform("This setup plan cannot be applied here.", (body["problem"] as? String) ?? described.problems)
        }
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        var fields: [(String, NSTextField)] = []
        for issuer in issuers {
            guard let keyId = issuer["key_id"] as? String, let name = issuer["issuer"] as? String else { continue }
            let label = NSTextField(wrappingLabelWithString: "Fingerprint that \(name) (key id \(keyId)) gave you by a call or another route. Do not copy it from this computer.")
            label.preferredMaxLayoutWidth = 460
            let field = NSTextField(string: "")
            field.placeholderString = "64 characters, 0-9 and a-f"
            field.translatesAutoresizingMaskIntoConstraints = false
            field.widthAnchor.constraint(equalToConstant: 460).isActive = true
            stack.addArrangedSubview(label)
            stack.addArrangedSubview(field)
            fields.append((keyId, field))
        }
        stack.layoutSubtreeIfNeeded()
        let size = stack.fittingSize
        stack.frame = NSRect(origin: .zero, size: size)
        // Python's summary, notices first, in a box of fixed height; the fields below it, scrolled if there are many.
        // However long either is, the alert keeps its Apply and Cancel buttons on the screen.
        let summaryBox = fixedBox(scrollingText(summary, width: 480, height: 200), width: 480, height: 200)
        let fieldsBox: NSView
        if size.height > 200 {
            let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: size.width + 20, height: 200))
            scroll.documentView = stack
            scroll.hasVerticalScroller = true
            fieldsBox = fixedBox(scroll, width: size.width + 20, height: 200)
        } else {
            fieldsBox = stack
        }
        let whole = NSStackView(views: [summaryBox, fieldsBox])
        whole.orientation = .vertical
        whole.alignment = .leading
        whole.spacing = 10
        whole.layoutSubtreeIfNeeded()
        whole.frame = NSRect(origin: .zero, size: whole.fittingSize)
        let alert = NSAlert()
        alert.messageText = "Administrator setup"
        alert.informativeText = "The box below is what admin-describe says about this plan. Read it before you apply."
        alert.accessoryView = whole
        alert.addButton(withTitle: "Apply")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = fields.first?.1
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { adminBusy = false; return }
        var arguments = ["admin-apply", "--expect-plan-sha256=\(digest)"]
        for (keyId, field) in fields { arguments.append("--expect-fingerprint=\(keyId)=\(field.stringValue)") }
        arguments += ["--", plan.path]
        runTool(arguments) { [weak self] applied in
            guard let self = self else { return }
            self.adminBusy = false
            if applied.status == 0 {
                self.inform("The setup plan was applied.", applied.output + "\nThe portal now restarts so that it reads the new configuration.")
                self.restartPortal()
            } else if applied.status == 4 {
                // Python says the new files are in place but a step after that did not finish.
                self.inform("The setup plan was applied, but a step after it did not finish.", applied.problems + "\nThe portal now restarts so that it reads the new configuration.")
                self.restartPortal()
            } else {
                self.inform("The setup plan was not applied.", applied.problems.isEmpty ? applied.output : applied.problems)
            }
        }
    }

    /// Stop the portal the way Quit does, then start it again so that it reads its configuration afresh. The old
    /// portal stays the current one until it has stopped, so a Quit meanwhile still waits for it as before.
    func restartPortal() {
        guard !quitting else { return }
        guard let running = process, running.isRunning else { process = nil; return startPortal() }
        retiring = running  // its exit is expected now, so it is not reported as a failure
        running.terminate()
        DispatchQueue.global().async { [weak self] in
            let end = Date().addingTimeInterval(6)
            while running.isRunning && Date() < end { Thread.sleep(forTimeInterval: 0.05) }
            if running.isRunning { kill(running.processIdentifier, SIGKILL) }
            DispatchQueue.main.async {
                guard let self = self, !self.quitting else { return }
                self.process = nil
                self.startPortal(replacing: true)
            }
        }
    }

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
        menu.addItem(withTitle: "Administrator setup\u{2026}", action: #selector(administratorSetup), keyEquivalent: "").target = self
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
