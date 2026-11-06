import Darwin
import Foundation

enum WarpTransportError: Error {
    case invalidConfiguration
    case unavailable
    case cancelled
}

final class WarpTransport {
    private let queue = DispatchQueue(label: "org.amnezia.warp-transport")
    private let interfaceLock = NSLock()
    private var interfaceIndex: UInt32
    private var handle: Int32 = -1
    private var timer: DispatchSourceTimer?
    private var readyHandlers: [(Error?) -> Void] = []
    private var failureHandler: ((Error) -> Void)?
    private var readinessHandler: ((Bool) -> Void)?
    private var readinessDeadline = Date.distantPast
    private var lastState: Int32 = -1
    private var hasStarted = false

    init(interfaceIndex: UInt32) {
        self.interfaceIndex = interfaceIndex
    }

    func start(underlay: Data, protocolName: String, configuration: Data,
               readinessHandler: @escaping (Bool) -> Void,
               failureHandler: @escaping (Error) -> Void,
               completion: @escaping (Result<Data, Error>) -> Void) {
        queue.async {
            guard self.handle < 0,
                  let underlayText = String(data: underlay, encoding: .utf8),
                  let configurationText = String(data: configuration, encoding: .utf8) else {
                DispatchQueue.main.async { completion(.failure(WarpTransportError.invalidConfiguration)) }
                return
            }
            let context = Unmanaged.passUnretained(self).toOpaque()
            let protect: amnezia_warp_protect = { socket, context in
                guard let context else { return false }
                return Unmanaged<WarpTransport>.fromOpaque(context).takeUnretainedValue().protectSocket(socket)
            }
            self.handle = underlayText.withCString { underlayPointer in
                protocolName.withCString { protocolPointer in
                    configurationText.withCString { configurationPointer in
                        amneziaWarpStart(UnsafeMutablePointer(mutating: underlayPointer),
                                         UnsafeMutablePointer(mutating: protocolPointer),
                                         UnsafeMutablePointer(mutating: configurationPointer), protect, context)
                    }
                }
            }
            guard self.handle > 0, let rewritten = amneziaWarpConfiguration(self.handle) else {
                self.closeNativeTransport()
                DispatchQueue.main.async { completion(.failure(WarpTransportError.unavailable)) }
                return
            }
            let rewrittenConfiguration = Data(String(cString: rewritten).utf8)
            amneziaWarpFree(rewritten)
            self.failureHandler = failureHandler
            self.readinessHandler = readinessHandler
            self.readyHandlers.append { error in
                if let error {
                    completion(.failure(error))
                } else {
                    completion(.success(rewrittenConfiguration))
                }
            }
            self.readinessDeadline = Date().addingTimeInterval(30)
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now(), repeating: .milliseconds(250))
            timer.setEventHandler { [weak self] in self?.checkReadiness() }
            self.timer = timer
            timer.resume()
        }
    }

    func rebind(interfaceIndex: UInt32, completion: @escaping (Error?) -> Void) {
        queue.async {
            self.interfaceLock.lock()
            self.interfaceIndex = interfaceIndex
            self.interfaceLock.unlock()
            guard self.handle > 0 else {
                DispatchQueue.main.async { completion(WarpTransportError.unavailable) }
                return
            }
            self.readyHandlers.append(completion)
            guard amneziaWarpRebind(self.handle) == 0 else {
                self.fail(WarpTransportError.unavailable)
                return
            }
            self.readinessDeadline = Date().addingTimeInterval(30)
            self.checkReadiness()
        }
    }

    func stop(completion: @escaping () -> Void) {
        queue.async {
            self.closeNativeTransport()
            self.completeReadyHandlers(WarpTransportError.cancelled)
            self.failureHandler = nil
            self.readinessHandler = nil
            DispatchQueue.main.async(execute: completion)
        }
    }

    private func protectSocket(_ socket: Int32) -> Bool {
        interfaceLock.lock()
        var index = interfaceIndex
        interfaceLock.unlock()
        guard index != 0 else { return false }
        return withUnsafePointer(to: &index) { pointer in
            setsockopt(socket, IPPROTO_IP, IP_BOUND_IF, pointer, socklen_t(MemoryLayout<UInt32>.size)) == 0
        }
    }

    private func checkReadiness() {
        guard handle > 0 else { return }
        let state = amneziaWarpState(handle)
        if state < 0 {
            fail(WarpTransportError.unavailable)
            return
        }
        if state == 0 && lastState == 1 {
            readinessDeadline = Date().addingTimeInterval(30)
        }
        if state == 0 && Date() > readinessDeadline {
            fail(WarpTransportError.unavailable)
            return
        }
        if state != lastState, let readinessHandler {
            DispatchQueue.main.async { readinessHandler(state == 1) }
        }
        lastState = state
        if state == 1 {
            hasStarted = true
            completeReadyHandlers(nil)
        }
    }

    private func completeReadyHandlers(_ error: Error?) {
        let handlers = readyHandlers
        readyHandlers.removeAll()
        DispatchQueue.main.async {
            for handler in handlers { handler(error) }
        }
    }

    private func fail(_ error: Error) {
        let wasStarted = hasStarted
        let failureHandler = self.failureHandler
        closeNativeTransport()
        completeReadyHandlers(error)
        if wasStarted, let failureHandler {
            DispatchQueue.main.async { failureHandler(error) }
        }
    }

    private func closeNativeTransport() {
        timer?.cancel()
        timer = nil
        if handle > 0 { amneziaWarpStop(handle) }
        handle = -1
        hasStarted = false
    }
}
