package org.amnezia.vpn

import android.content.Context
import androidx.annotation.Keep
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.util.LibraryLoader.loadSharedLibrary
import org.json.JSONObject

@Keep
internal class WarpTransport(
    private val context: Context,
    private val protect: (Int) -> Boolean
) : AutoCloseable {
    private var handle = 0L

    @Synchronized
    fun start(underlay: JSONObject, protocol: String, configuration: JSONObject): JSONObject {
        check(handle == 0L)
        loadSharedLibrary(context, "wg-go")
        handle = nativeStart(underlay.toString(), protocol, configuration.toString())
        if (handle == 0L) throw VpnStartException("Failed to start WARP transport")
        try {
            return JSONObject(nativeConfiguration(handle)
                ?: throw VpnStartException("Missing WARP transport configuration"))
        } catch (error: Exception) {
            close()
            throw error
        }
    }

    @Synchronized
    fun state(): Int = if (handle == 0L) -1 else nativeState(handle)

    suspend fun awaitReady() {
        try {
            withTimeout(30_000L) {
                while (true) {
                    when (state()) {
                        1 -> return@withTimeout
                        0 -> delay(100L)
                        else -> throw VpnStartException("WARP transport unavailable")
                    }
                }
            }
        } catch (error: TimeoutCancellationException) {
            throw VpnStartException("WARP transport handshake timed out")
        }
        currentCoroutineContext().ensureActive()
    }

    @Synchronized
    fun rebind() {
        if (handle == 0L || !nativeRebind(handle)) {
            throw VpnStartException("Failed to rebind WARP transport")
        }
    }

    @Synchronized
    override fun close() {
        if (handle != 0L) {
            nativeStop(handle)
            handle = 0L
        }
    }

    fun protectSocket(socket: Int): Boolean = protect(socket)

    private external fun nativeStart(underlay: String, protocol: String, configuration: String): Long
    private external fun nativeConfiguration(handle: Long): String?
    private external fun nativeState(handle: Long): Int
    private external fun nativeRebind(handle: Long): Boolean
    private external fun nativeStop(handle: Long)
}
