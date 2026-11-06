package org.amnezia.vpn

import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST
import android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.PowerManager
import android.os.Process
import androidx.annotation.MainThread
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap
import kotlin.LazyThreadSafetyMode.NONE
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.CONNECTING
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTING
import org.amnezia.vpn.protocol.ProtocolState.RECONNECTING
import org.amnezia.vpn.protocol.ProtocolState.UNKNOWN
import org.amnezia.vpn.protocol.VpnException
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.putStatus
import org.amnezia.vpn.util.LoadLibraryException
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.Prefs
import org.amnezia.vpn.util.net.NetworkState
import org.amnezia.vpn.util.net.TrafficStats
import org.json.JSONException
import org.json.JSONObject

private const val TAG = "AmneziaVpnService"

val ACTION_DISCONNECT = "${BuildConfig.APPLICATION_ID}.action.disconnect"
val ACTION_CONNECT = "${BuildConfig.APPLICATION_ID}.action.connect"

const val MSG_VPN_CONFIG = "VPN_CONFIG"
const val MSG_ERROR = "ERROR"
const val MSG_SAVE_LOGS = "SAVE_LOGS"
const val MSG_CLIENT_NAME = "CLIENT_NAME"

const val AFTER_PERMISSION_CHECK = "AFTER_PERMISSION_CHECK"
private const val PREFS_CONFIG_KEY = "LAST_CONF"
private const val PREFS_SERVER_NAME = "LAST_SERVER_NAME"
private const val PREFS_SERVER_INDEX = "LAST_SERVER_INDEX"
// private const val STATISTICS_SENDING_TIMEOUT = 1000L
private const val TRAFFIC_STATS_UPDATE_TIMEOUT = 1000L
private const val DISCONNECT_TIMEOUT = 5000L
private const val STOP_SERVICE_TIMEOUT = 5000L

@SuppressLint("Registered")
open class AmneziaVpnService : VpnService() {

    private lateinit var mainScope: CoroutineScope
    private lateinit var connectionScope: CoroutineScope
    private var isServiceBound = false
    private var vpnProto: VpnProto? = null
    private var protocolState = MutableStateFlow(UNKNOWN)
    private var serverName: String? = null
    private var serverIndex: Int = -1

    private val isConnected
        get() = protocolState.value == CONNECTED

    private val isDisconnected
        get() = protocolState.value == DISCONNECTED

    private val isUnknown
        get() = protocolState.value == UNKNOWN

    private var connectionJob: Job? = null
    private var disconnectionJob: Job? = null
    private var trafficStatsUpdateJob: Job? = null
    private val protocolOperation = Mutex()
    private var activeProtocol: Protocol? = null
    @Volatile private var warpTransport: WarpTransport? = null
    private var warpMonitorJob: Job? = null
    // private var statisticsSendingJob: Job? = null
    private lateinit var networkState: NetworkState
    private lateinit var trafficStats: TrafficStats
    private var controlReceiver: BroadcastReceiver? = null
    private var notificationStateReceiver: BroadcastReceiver? = null
    private var screenOnReceiver: BroadcastReceiver? = null
    private var screenOffReceiver: BroadcastReceiver? = null
    private val clientMessengers = ConcurrentHashMap<Messenger, IpcMessenger>()

    private val isActivityConnected
        get() = clientMessengers.any { it.value.name == ACTIVITY_MESSENGER_NAME }

    private val connectionExceptionHandler = CoroutineExceptionHandler { context, e ->
        mainScope.launch {
            val failedJob = context[Job] ?: return@launch
            if (connectionJob !== failedJob && disconnectionJob !== failedJob) return@launch
            if (connectionJob === failedJob) connectionJob = null
            if (disconnectionJob === failedJob) disconnectionJob = null
            protocolState.value = DISCONNECTED
            when (e) {
                is IllegalArgumentException,
                is VpnStartException,
                is VpnException -> onError(e.message ?: e.toString())

                is JSONException,
                is BadConfigException -> onError("VPN config format error: ${e.message}")

                is LoadLibraryException -> onError("${e.message}. Caused: ${e.cause?.message}")

                is UnknownHostException -> onError("Unknown host")

                else -> throw e
            }
        }
    }

    private val actionMessageHandler: Handler by lazy(NONE) {
        object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                val action = msg.extractIpcMessage<Action>()
                Log.d(TAG, "Handle action: $action")
                when (action) {
                    Action.REGISTER_CLIENT -> {
                        val clientName = msg.data.getString(MSG_CLIENT_NAME)
                        val messenger = IpcMessenger(msg.replyTo, clientName)
                        clientMessengers[msg.replyTo] = messenger
                        Log.d(TAG, "Messenger client '$clientName' was registered")
                        // if (clientName == ACTIVITY_MESSENGER_NAME && isConnected) launchSendingStatistics()
                    }

                    Action.UNREGISTER_CLIENT -> {
                        clientMessengers.remove(msg.replyTo)?.let {
                            Log.d(TAG, "Messenger client '${it.name}' was unregistered")
                            // if (it.name == ACTIVITY_MESSENGER_NAME) stopSendingStatistics()
                        }
                    }

                    Action.CONNECT -> {
                        connect(msg.data.getString(MSG_VPN_CONFIG))
                    }

                    Action.DISCONNECT -> {
                        disconnect()
                    }

                    Action.REQUEST_STATUS -> {
                        clientMessengers[msg.replyTo]?.let { clientMessenger ->
                            clientMessenger.send {
                                ServiceEvent.STATUS.packToMessage {
                                    putStatus(this@AmneziaVpnService.protocolState.value)
                                }
                            }
                        }
                    }

                    Action.NOTIFICATION_PERMISSION_GRANTED -> {
                        enableNotification()
                    }

                    Action.SET_SAVE_LOGS -> {
                        Log.saveLogs = msg.data.getBoolean(MSG_SAVE_LOGS)
                    }
                }
            }
        }
    }

    private val vpnServiceMessenger: Messenger by lazy(NONE) {
        Messenger(actionMessageHandler)
    }

    /**
     * Notification setup
     */
    private val foregroundServiceTypeCompat
        get() = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> FOREGROUND_SERVICE_TYPE_MANIFEST
            else -> 0
        }

    private val serviceNotification: ServiceNotification by lazy(NONE) { ServiceNotification(this) }

    /**
     * Service overloaded methods
     */
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Create Amnezia VPN service")
        mainScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        connectionScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + connectionExceptionHandler)
        loadServerData()
        launchProtocolStateHandler()
        networkState = NetworkState(this, ::reconnect)
        trafficStats = TrafficStats()
        registerBroadcastReceivers()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val isAlwaysOn = intent != null && intent.action == SERVICE_INTERFACE

        if (isAlwaysOn) {
            Log.d(TAG, "Start service via Always-on")
            connect()
        } else if (intent?.getBooleanExtra(AFTER_PERMISSION_CHECK, false) == true) {
            Log.d(TAG, "Start service after permission check")
            connect()
        } else {
            Log.d(TAG, "Start service")
            connect(intent?.getStringExtra(MSG_VPN_CONFIG))
        }
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID,
            serviceNotification.buildNotification(serverName, vpnProto?.label, protocolState.value),
            foregroundServiceTypeCompat
        )
        return START_REDELIVER_INTENT
    }

    override fun onBind(intent: Intent?): IBinder? {
        Log.d(TAG, "onBind by $intent")
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        isServiceBound = true
        return vpnServiceMessenger.binder
    }

    override fun onUnbind(intent: Intent?): Boolean {
        Log.d(TAG, "onUnbind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            if (clientMessengers.isEmpty()) {
                isServiceBound = false
                if (isUnknown || isDisconnected) stopService()
            }
        }
        return true
    }

    override fun onRebind(intent: Intent?) {
        Log.d(TAG, "onRebind by $intent")
        if (intent?.action != SERVICE_INTERFACE) {
            isServiceBound = true
        }
        super.onRebind(intent)
    }

    override fun onRevoke() {
        Log.d(TAG, "onRevoke")
        // Calls to onRevoke() method may not happen on the main thread of the process
        mainScope.launch {
            disconnect()
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "Destroy service")
        unregisterBroadcastReceivers()
        runBlocking {
            disconnect()
            disconnectionJob?.join()
        }
        connectionScope.cancel()
        mainScope.cancel()
        super.onDestroy()
    }

    private fun stopService() {
        Log.d(TAG, "Stop service")
        // the coroutine below will be canceled during the onDestroy call
        mainScope.launch {
            delay(STOP_SERVICE_TIMEOUT)
            Log.w(TAG, "Stop service timeout, kill process")
            Process.killProcess(Process.myPid())
        }
        stopSelf()
    }

    private fun registerBroadcastReceivers() {
        Log.d(TAG, "Register broadcast receivers")
        controlReceiver = registerBroadcastReceiver(
            arrayOf(ACTION_CONNECT, ACTION_DISCONNECT), ContextCompat.RECEIVER_NOT_EXPORTED
        ) {
            it?.action?.let { action ->
                Log.v(TAG, "Broadcast request received: $action")
                when (action) {
                    ACTION_CONNECT -> connect()
                    ACTION_DISCONNECT -> disconnect()
                    else -> Log.w(TAG, "Unknown action received: $action")
                }
            }
        }

        notificationStateReceiver = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            registerBroadcastReceiver(
                arrayOf(
                    NotificationManager.ACTION_NOTIFICATION_CHANNEL_BLOCK_STATE_CHANGED,
                    NotificationManager.ACTION_APP_BLOCK_STATE_CHANGED
                )
            ) {
                val state = it?.getBooleanExtra(NotificationManager.EXTRA_BLOCKED_STATE, false)
                Log.v(TAG, "Notification state changed: ${it?.action}, blocked = $state")
                if (state == false) {
                    enableNotification()
                } else {
                    disableNotification()
                }
            }
        } else null

        registerScreenStateBroadcastReceivers()
    }

    private fun registerScreenStateBroadcastReceivers() {
        if (serviceNotification.isNotificationEnabled()) {
            Log.d(TAG, "Register screen state broadcast receivers")
            screenOnReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_ON) {
                if (isConnected && serviceNotification.isNotificationEnabled()) startTrafficStatsUpdateJob()
            }

            screenOffReceiver = registerBroadcastReceiver(Intent.ACTION_SCREEN_OFF) {
                stopTrafficStatsUpdateJob()
            }
        }
    }

    private fun unregisterScreenStateBroadcastReceivers() {
        Log.d(TAG, "Unregister screen state broadcast receivers")
        unregisterBroadcastReceiver(screenOnReceiver)
        unregisterBroadcastReceiver(screenOffReceiver)
        screenOnReceiver = null
        screenOffReceiver = null
    }

    private fun unregisterBroadcastReceivers() {
        Log.d(TAG, "Unregister broadcast receivers")
        unregisterBroadcastReceiver(controlReceiver)
        unregisterBroadcastReceiver(notificationStateReceiver)
        unregisterScreenStateBroadcastReceivers()
        controlReceiver = null
        notificationStateReceiver = null
    }

    /**
     * Methods responsible for processing VPN connection
     */
    private fun launchProtocolStateHandler() {
        mainScope.launch {
            // drop first default UNKNOWN state
            protocolState.drop(1).collect { protocolState ->
                Log.d(TAG, "Protocol state changed: $protocolState")

                serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState)

                clientMessengers.send {
                    ServiceEvent.STATUS_CHANGED.packToMessage {
                        putStatus(protocolState)
                    }
                }

                VpnStateStore.store { VpnState(protocolState, serverName, serverIndex, vpnProto) }

                when (protocolState) {
                    CONNECTED -> {
                        networkState.bindNetworkListener()
                        // if (isActivityConnected) launchSendingStatistics()
                        launchTrafficStatsUpdate()
                    }

                    DISCONNECTED -> {
                        networkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        val transport = warpTransport
                        connectionScope.launch {
                            protocolOperation.withLock {
                                if (isDisconnected && transport != null && warpTransport === transport) stopWarpTransport()
                            }
                        }
                        // stopSendingStatistics()
                        if (!isServiceBound) stopService()
                    }

                    DISCONNECTING -> {
                        networkState.unbindNetworkListener()
                        stopTrafficStatsUpdateJob()
                        // stopSendingStatistics()
                    }

                    RECONNECTING -> {
                        stopTrafficStatsUpdateJob()
                        // stopSendingStatistics()
                    }

                    CONNECTING, UNKNOWN -> {}
                }
            }
        }
    }

/*  @MainThread
    private fun launchSendingStatistics() {
        if (isServiceBound && isConnected) {
            statisticsSendingJob = mainScope.launch {
                while (true) {
                    clientMessenger.send {
                        ServiceEvent.STATISTICS_UPDATE.packToMessage {
                            putStatistics(protocol?.statistics ?: Statistics.EMPTY_STATISTICS)
                        }
                    }
                    delay(STATISTICS_SENDING_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopSendingStatistics() {
        statisticsSendingJob?.cancel()
    } */

    @MainThread
    private fun enableNotification() {
        registerScreenStateBroadcastReceivers()
        serviceNotification.updateNotification(serverName, vpnProto?.label, protocolState.value)
        launchTrafficStatsUpdate()
    }

    @MainThread
    private fun disableNotification() {
        unregisterScreenStateBroadcastReceivers()
        stopTrafficStatsUpdateJob()
    }

    @MainThread
    private fun launchTrafficStatsUpdate() {
        stopTrafficStatsUpdateJob()
        if (isConnected &&
            serviceNotification.isNotificationEnabled() &&
            getSystemService<PowerManager>()?.isInteractive != false
        ) {
            Log.v(TAG, "Launch traffic stats update")
            trafficStats.reset()
            startTrafficStatsUpdateJob()
        }
    }

    @MainThread
    private fun startTrafficStatsUpdateJob() {
        if (trafficStatsUpdateJob == null && trafficStats.isSupported()) {
            Log.d(TAG, "Start traffic stats update")
            trafficStatsUpdateJob = mainScope.launch {
                while (true) {
                    trafficStats.getSpeed().let { speed ->
                        if (isConnected) {
                            serviceNotification.updateSpeed(speed)
                        }
                    }
                    delay(TRAFFIC_STATS_UPDATE_TIMEOUT)
                }
            }
        }
    }

    @MainThread
    private fun stopTrafficStatsUpdateJob() {
        Log.d(TAG, "Stop traffic stats update")
        trafficStatsUpdateJob?.cancel()
        trafficStatsUpdateJob = null
    }

    @MainThread
    private fun connect(vpnConfig: String? = null) {
        if (vpnConfig == null) {
            connectToVpn(Prefs.load(PREFS_CONFIG_KEY))
        } else {
            Prefs.save(PREFS_CONFIG_KEY, vpnConfig)
            connectToVpn(vpnConfig)
        }
    }

    @MainThread
    private fun connectToVpn(vpnConfig: String) {
        if (isConnected || protocolState.value == CONNECTING || protocolState.value == RECONNECTING) return

        Log.d(TAG, "Start VPN connection")

        val config = parseConfigToJson(vpnConfig)
        saveServerData(config)
        if (config == null) {
            onError("Invalid VPN config")
            protocolState.value = DISCONNECTED
            return
        }

        try {
            vpnProto = VpnProto.get(config.getString("protocol"))
        } catch (e: Exception) {
            onError("Invalid VPN config: ${e.message}")
            protocolState.value = DISCONNECTED
            return
        }

        protocolState.value = CONNECTING

        if (!checkPermission()) {
            protocolState.value = DISCONNECTED
            return
        }

        val pendingDisconnection = disconnectionJob
        val requestedProto = vpnProto
        connectionJob = connectionScope.launch {
            pendingDisconnection?.join()
            if (disconnectionJob === pendingDisconnection) disconnectionJob = null

            protocolOperation.withLock {
                requestedProto?.protocol?.let { protocol ->
                    try {
                        stopActiveProtocol()
                        currentCoroutineContext().ensureActive()
                        protocolState.value = CONNECTING
                        val preparedConfig = prepareWarpTransport(config)
                        currentCoroutineContext().ensureActive()
                        protocol.initialize(applicationContext, protocolState, ::onError)
                        activeProtocol = protocol
                        protocol.startVpn(preparedConfig, Builder(), ::protect)
                        currentCoroutineContext().ensureActive()
                        startWarpMonitor()
                    } catch (error: Exception) {
                        stopActiveProtocol()
                        throw error
                    }
                }
            }
        }
    }

    private suspend fun prepareWarpTransport(config: JSONObject): JSONObject {
        stopWarpTransport()
        if (!config.has("warpUnderlay")) return config
        val underlay = config.optJSONObject("warpUnderlay")
            ?: throw BadConfigException("Invalid WARP transport configuration")
        val protocol = config.getString("protocol").lowercase()
        val key = "${protocol}_config_data"
        val protocolConfig = config.optJSONObject(key)
            ?: throw BadConfigException("Missing protocol configuration for WARP transport")
        val transport = WarpTransport(applicationContext, ::protect)
        warpTransport = transport
        val rewritten = transport.start(underlay, protocol, protocolConfig)
        transport.awaitReady()
        return JSONObject(config.toString()).put(key, rewritten)
    }

    private fun startWarpMonitor() {
        val transport = warpTransport ?: return
        warpMonitorJob?.cancel()
        warpMonitorJob = connectionScope.launch {
            var awaitingHandshake = false
            while (true) {
                when (transport.state()) {
                    0 -> {
                        if (protocolState.value == CONNECTED) {
                            awaitingHandshake = true
                            protocolState.value = RECONNECTING
                        }
                    }
                    1 -> {
                        if (awaitingHandshake && protocolState.value == RECONNECTING) {
                            awaitingHandshake = false
                            protocolState.value = CONNECTED
                        }
                    }
                    else -> {
                        mainScope.launch {
                            if (warpTransport === transport) {
                                onError("WARP transport unavailable")
                                disconnect()
                            }
                        }
                        return@launch
                    }
                }
                delay(250L)
            }
        }
    }

    private fun stopWarpTransport() {
        warpMonitorJob?.cancel()
        warpMonitorJob = null
        warpTransport?.close()
        warpTransport = null
    }

    private fun stopActiveProtocol() {
        val protocol = activeProtocol
        activeProtocol = null
        try {
            protocol?.stopVpn()
        } finally {
            stopWarpTransport()
            if (protocol == null && protocolState.value == DISCONNECTING) {
                protocolState.value = DISCONNECTED
            }
        }
    }

    @MainThread
    private fun disconnect() {
        if (isUnknown || isDisconnected || protocolState.value == DISCONNECTING) return

        Log.d(TAG, "Stop VPN connection")

        protocolState.value = DISCONNECTING

        val pendingConnection = connectionJob
        disconnectionJob = connectionScope.launch {
            pendingConnection?.cancelAndJoin()
            if (connectionJob === pendingConnection) connectionJob = null

            protocolOperation.withLock {
                stopActiveProtocol()
            }

            try {
                withTimeout(DISCONNECT_TIMEOUT) {
                    // waiting for disconnect state
                    protocolState.first { it == DISCONNECTED }
                }
            } catch (e: TimeoutCancellationException) {
                Log.w(TAG, "Disconnect timeout")
                stopService()
            }
        }
    }

    @MainThread
    private fun reconnect() {
        if (!isConnected) return

        Log.d(TAG, "Reconnect VPN")

        protocolState.value = RECONNECTING

        connectionJob = connectionScope.launch {
            protocolOperation.withLock {
                try {
                    warpMonitorJob?.cancelAndJoin()
                    warpMonitorJob = null
                    warpTransport?.let { transport ->
                        transport.rebind()
                        transport.awaitReady()
                    }
                    currentCoroutineContext().ensureActive()
                    activeProtocol?.reconnectVpn(Builder(), ::protect)
                    startWarpMonitor()
                } catch (error: Exception) {
                    stopActiveProtocol()
                    throw error
                }
            }
        }
    }

    /**
     * Utils methods
     */
    private fun onError(msg: String) {
        Log.e(TAG, msg)
        mainScope.launch {
            clientMessengers.send {
                ServiceEvent.ERROR.packToMessage {
                    putString(MSG_ERROR, msg)
                }
            }
        }
    }

    private fun parseConfigToJson(vpnConfig: String): JSONObject? =
        if (vpnConfig.isBlank()) {
            null
        } else {
            try {
                JSONObject(vpnConfig)
            } catch (e: JSONException) {
                onError("Invalid VPN config json format: ${e.message}")
                null
            }
        }

    private fun saveServerData(config: JSONObject?) {
        serverName = config?.opt("description") as String?
        serverIndex = config?.opt("serverIndex") as Int? ?: -1
        Log.d(TAG, "Save server data: ($serverIndex, $serverName)")
        Prefs.save(PREFS_SERVER_NAME, serverName)
        Prefs.save(PREFS_SERVER_INDEX, serverIndex)
    }

    private fun loadServerData() {
        serverName = Prefs.load<String>(PREFS_SERVER_NAME).ifBlank { null }
        if (serverName != null) serverIndex = Prefs.load(PREFS_SERVER_INDEX)
        Log.d(TAG, "Load server data: ($serverIndex, $serverName)")
    }

    private fun checkPermission(): Boolean =
        if (prepare(applicationContext) != null) {
            Intent(this, VpnRequestActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(EXTRA_PROTOCOL, vpnProto)
            }.also {
                startActivity(it)
            }
            false
        } else {
            true
        }

    companion object {
        fun isRunning(context: Context, processName: String): Boolean =
            context.getSystemService<ActivityManager>()!!.runningAppProcesses.any {
                it.processName == processName && it.importance <= IMPORTANCE_FOREGROUND_SERVICE
            }
    }
}
