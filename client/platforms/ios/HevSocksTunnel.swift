import HevSocks5Tunnel
import Foundation
import NetworkExtension

final class Socks5Tunnel {
    private let lock = NSLock()
    private var stopRequested = false
    private var isRunning = false
    private var didRequestStop = false
    private var timer: DispatchSourceTimer?
    private var startHandler: ((Error?) -> Void)?
    private var stopHandlers: [() -> Void] = []

    private static var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    private static var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            return nil
        }
        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))
        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else {
                return nil
            }
            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize
            )
            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    func start(withConfig filePath: String,
               failureHandler: @escaping (Error) -> Void,
               completionHandler: @escaping (Error?) -> Void) {
        guard !isRunning else {
            completionHandler(WarpTransportError.unavailable)
            return
        }
        guard let fileDescriptor = Self.tunnelFileDescriptor else {
            completionHandler(WarpTransportError.unavailable)
            return
        }
        isRunning = true
        didRequestStop = false
        lock.lock()
        stopRequested = false
        lock.unlock()
        startHandler = completionHandler
        let deadline = Date().addingTimeInterval(30)
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now(), repeating: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            if self.isStopping {
                if !self.didRequestStop, hev_socks5_tunnel_is_running() != 0 {
                    self.didRequestStop = true
                    hev_socks5_tunnel_quit()
                }
            } else if hev_socks5_tunnel_is_running() != 0 {
                let handler = self.startHandler
                self.startHandler = nil
                handler?(nil)
            } else if Date() > deadline, let handler = self.startHandler {
                self.startHandler = nil
                handler(WarpTransportError.unavailable)
            }
        }
        self.timer = timer
        timer.resume()
        DispatchQueue.global(qos: .utility).async {
            if !self.isStopping {
                _ = hev_socks5_tunnel_main(filePath.cString(using: .utf8), fileDescriptor)
            }
            DispatchQueue.main.async {
                self.isRunning = false
                self.timer?.cancel()
                self.timer = nil
                let handler = self.startHandler
                self.startHandler = nil
                if let handler {
                    handler(self.isStopping ? WarpTransportError.cancelled : WarpTransportError.unavailable)
                } else if !self.isStopping {
                    failureHandler(WarpTransportError.unavailable)
                }
                let handlers = self.stopHandlers
                self.stopHandlers.removeAll()
                for handler in handlers { handler() }
            }
        }
    }

    func stop(completionHandler: @escaping () -> Void) {
        guard isRunning else {
            completionHandler()
            return
        }
        stopHandlers.append(completionHandler)
        lock.lock()
        stopRequested = true
        lock.unlock()
    }

    private var isStopping: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopRequested
    }
}
