package com.pureshield.adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AdBlockVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.pureshield.adblocker.START_VPN"
        const val ACTION_STOP = "com.pureshield.adblocker.STOP_VPN"
        private const val CHANNEL_ID = "pureshield_vpn_channel"
        private const val NOTIFICATION_ID = 1001

        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VIRTUAL_DNS = "10.0.0.1"

        private const val UPSTREAM_DNS_PRIMARY = "1.1.1.1"
        private const val UPSTREAM_DNS_SECONDARY = "8.8.8.8"

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val isActive = AtomicBoolean(false)
    private var readerThread: Thread? = null
    private var dnsExecutor: ExecutorService? = null
    private val writeLock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        BlocklistManager.init(applicationContext)

        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> {
                startVpn()
                return START_STICKY
            }
        }
    }

    private fun startVpn() {
        if (isActive.getAndSet(true)) {
            updateNotification()
            return
        }

        createNotificationChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        try {
            val builder = Builder()
                .setSession("PureShield 系統廣告攔截")
                .setMtu(1500)
                .addAddress(VPN_ADDRESS, 32)
                .addDnsServer(VIRTUAL_DNS)
                .addRoute(VIRTUAL_DNS, 32)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                isActive.set(false)
                isRunning = false
                stopSelf()
                return
            }

            isRunning = true
            dnsExecutor = Executors.newFixedThreadPool(8)

            readerThread = Thread({ runTunLoop() }, "PureShield-TUN-Loop").apply {
                isDaemon = true
                start()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
        }
    }

    private fun runTunLoop() {
        val pfd = vpnInterface ?: return
        val inputStream = FileInputStream(pfd.fileDescriptor)
        val outputStream = FileOutputStream(pfd.fileDescriptor)
        val buffer = ByteArray(32767)

        try {
            while (isActive.get() && !Thread.currentThread().isInterrupted) {
                val length = inputStream.read(buffer)
                if (length <= 0) {
                    if (length < 0) break
                    continue
                }

                val packetCopy = buffer.copyOfRange(0, length)
                val parsed = DnsPacketHelper.parseDnsQuery(packetCopy, length) ?: continue

                val domain = parsed.domain
                val checkResult = BlocklistManager.checkDomain(domain)
                val blocked = checkResult.blocked
                BlocklistManager.recordQuery(
                    applicationContext,
                    domain,
                    parsed.qType,
                    checkResult
                )

                if (blocked) {
                    val blockedResponse = DnsPacketHelper.buildBlockedDnsResponse(packetCopy, parsed)
                    synchronized(writeLock) {
                        try {
                            outputStream.write(blockedResponse)
                            outputStream.flush()
                        } catch (_: Exception) {
                        }
                    }
                    if (BlocklistManager.sessionBlockedCount.get() % 5 == 0) {
                        updateNotification()
                    }
                } else {
                    dnsExecutor?.execute {
                        forwardCleanDnsQuery(packetCopy, parsed, outputStream)
                    }
                }
            }
        } catch (_: Exception) {
        } finally {
            try {
                inputStream.close()
            } catch (_: Exception) {
            }
            try {
                outputStream.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun forwardCleanDnsQuery(
        requestPacket: ByteArray,
        parsed: DnsPacketHelper.ParsedDnsQuery,
        outputStream: FileOutputStream
    ) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            protect(socket)
            socket.soTimeout = 3500

            val dnsPayload = requestPacket.copyOfRange(
                parsed.dnsPayloadOffset,
                parsed.dnsPayloadOffset + parsed.dnsPayloadLength
            )

            val upstreamAddr = InetAddress.getByName(UPSTREAM_DNS_PRIMARY)
            val outPacket = DatagramPacket(dnsPayload, dnsPayload.size, upstreamAddr, 53)
            socket.send(outPacket)

            val respBuf = ByteArray(1500)
            val inPacket = DatagramPacket(respBuf, respBuf.size)
            try {
                socket.receive(inPacket)
            } catch (_: Exception) {
                val backupAddr = InetAddress.getByName(UPSTREAM_DNS_SECONDARY)
                val retryPacket = DatagramPacket(dnsPayload, dnsPayload.size, backupAddr, 53)
                socket.send(retryPacket)
                socket.receive(inPacket)
            }

            val dnsRespBytes = respBuf.copyOfRange(0, inPacket.length)
            val wrappedIpUdp = DnsPacketHelper.wrapDnsResponseInIpUdp(
                requestPacket,
                parsed.ipHeaderLength,
                dnsRespBytes
            )

            synchronized(writeLock) {
                if (isActive.get()) {
                    outputStream.write(wrappedIpUdp)
                    outputStream.flush()
                }
            }
        } catch (_: Exception) {
        } finally {
            socket?.close()
        }
    }

    private fun stopVpn() {
        isActive.set(false)
        isRunning = false

        readerThread?.interrupt()
        readerThread = null

        dnsExecutor?.shutdownNow()
        dnsExecutor = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PureShield 廣告攔截防護狀態",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "顯示背景 DNS 廣告攔截器的運作狀態與統計"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = Intent(this, MainActivity::class.java)
        val pendingOpen = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, AdBlockVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val blocked = BlocklistManager.sessionBlockedCount.get()
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield_logo)
            .setContentTitle("PureShield 廣告防護運作中")
            .setContentText("本次已為瀏覽器攔截 $blocked 次廣告請求")
            .setOngoing(true)
            .setContentIntent(pendingOpen)
            .addAction(0, "停止防護", pendingStop)
            .build()
    }

    private fun updateNotification() {
        if (!isActive.get()) return
        val nm = getSystemService(NotificationManager::class.java)
        nm?.notify(NOTIFICATION_ID, buildNotification())
    }
}
