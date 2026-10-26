package com.pureshield.adblocker

import java.io.ByteArrayOutputStream
import java.util.Locale

/**
 * 負責解析 TUN 虛擬網卡攔截到的 IPv4 + UDP + DNS 封包，
 * 以及封裝正常轉發回應或本地阻擋回應（NXDOMAIN）的封包工具類。
 */
object DnsPacketHelper {

    data class ParsedDnsQuery(
        val domain: String,
        val qType: Int,
        val ipHeaderLength: Int,
        val dnsPayloadOffset: Int,
        val dnsPayloadLength: Int,
        val questionEndOffset: Int
    )

    /**
     * 解析原始 IPv4 封包，若為 UDP Port 53 的 DNS 查詢，則回傳解析後的網域名稱與偏移量資訊
     */
    fun parseDnsQuery(packet: ByteArray, length: Int): ParsedDnsQuery? {
        if (length < 28) return null // 最小 IPv4(20) + UDP(8)

        // 檢查是否為 IPv4 (Version == 4)
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        if (ipHeaderLen < 20 || length < ipHeaderLen + 8 + 12) return null

        // 檢查是否為 UDP 協定 (Protocol == 17)
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null

        // 檢查目標連接埠是否為 53 (DNS)
        val destPort = ((packet[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                (packet[ipHeaderLen + 3].toInt() and 0xFF)
        if (destPort != 53) return null

        val dnsOffset = ipHeaderLen + 8
        val dnsLength = length - dnsOffset
        if (dnsLength < 12) return null

        // 檢查 QDCOUNT (問題數量) 是否大於 0
        val qdCount = ((packet[dnsOffset + 4].toInt() and 0xFF) shl 8) or
                (packet[dnsOffset + 5].toInt() and 0xFF)
        if (qdCount <= 0) return null

        // 解析 QNAME (網域名稱)
        var pos = dnsOffset + 12
        val domainBuilder = StringBuilder()

        while (pos < length) {
            val labelLen = packet[pos].toInt() and 0xFF
            if (labelLen == 0) {
                pos++ // 跳過結尾的 0x00
                break
            }
            // 若遇到壓縮指標則中止（一般單一查詢不會在第一個 QNAME 出現）
            if ((labelLen and 0xC0) == 0xC0) {
                return null
            }
            pos++
            if (pos + labelLen > length) return null

            if (domainBuilder.isNotEmpty()) {
                domainBuilder.append('.')
            }
            for (i in 0 until labelLen) {
                domainBuilder.append((packet[pos + i].toInt() and 0xFF).toChar())
            }
            pos += labelLen
        }

        // QNAME 後方必須有 QTYPE (2 bytes) 與 QCLASS (2 bytes)
        if (pos + 4 > length) return null
        val qType = ((packet[pos].toInt() and 0xFF) shl 8) or (packet[pos + 1].toInt() and 0xFF)
        val questionEnd = pos + 4

        val domain = domainBuilder.toString().lowercase(Locale.ROOT).trimEnd('.')
        if (domain.isEmpty()) return null

        return ParsedDnsQuery(
            domain = domain,
            qType = qType,
            ipHeaderLength = ipHeaderLen,
            dnsPayloadOffset = dnsOffset,
            dnsPayloadLength = dnsLength,
            questionEndOffset = questionEnd
        )
    }

    /**
     * 建構本地阻擋廣告的 DNS 回應封包（回傳 NXDOMAIN，讓瀏覽器立即放棄載入廣告資源，零延遲）
     */
    fun buildBlockedDnsResponse(requestPacket: ByteArray, parsed: ParsedDnsQuery): ByteArray {
        val dnsStart = parsed.dnsPayloadOffset
        val questionSectionLen = parsed.questionEndOffset - (dnsStart + 12)

        val out = ByteArrayOutputStream()
        // 1. Transaction ID (與請求相同)
        out.write(requestPacket[dnsStart].toInt())
        out.write(requestPacket[dnsStart + 1].toInt())

        // 2. Flags: 0x8183 (Standard query response, No such name / NXDOMAIN)
        out.write(0x81)
        out.write(0x83)

        // 3. QDCOUNT = 1
        out.write(0x00)
        out.write(0x01)

        // 4. ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        for (i in 0 until 6) {
            out.write(0x00)
        }

        // 5. 複製原始 Question 區段 (QNAME + QTYPE + QCLASS)
        out.write(requestPacket, dnsStart + 12, questionSectionLen)

        val dnsResponsePayload = out.toByteArray()
        return wrapDnsResponseInIpUdp(requestPacket, parsed.ipHeaderLength, dnsResponsePayload)
    }

    /**
     * 將 DNS 回應 Payload 封裝為完整的 IPv4 + UDP 封包（交換來源與目的 IP/Port 並計算 IPv4 Checksum）
     */
    fun wrapDnsResponseInIpUdp(
        requestPacket: ByteArray,
        reqIpHeaderLen: Int,
        dnsPayload: ByteArray
    ): ByteArray {
        val totalLen = 20 + 8 + dnsPayload.size
        val response = ByteArray(totalLen)

        // --- IPv4 Header (20 bytes) ---
        response[0] = 0x45.toByte() // Version 4, IHL 5 (20 bytes)
        response[1] = 0x00.toByte() // TOS
        response[2] = ((totalLen ushr 8) and 0xFF).toByte()
        response[3] = (totalLen and 0xFF).toByte()

        // Identification (沿用請求或隨機)
        response[4] = requestPacket[4]
        response[5] = requestPacket[5]

        // Flags & Fragment Offset (Don't Fragment = 0x4000)
        response[6] = 0x40.toByte()
        response[7] = 0x00.toByte()

        // TTL = 64, Protocol = 17 (UDP)
        response[8] = 64.toByte()
        response[9] = 17.toByte()

        // Checksum 先填 0，稍後計算
        response[10] = 0
        response[11] = 0

        // 交換 Source IP 與 Destination IP
        System.arraycopy(requestPacket, 16, response, 12, 4)
        System.arraycopy(requestPacket, 12, response, 16, 4)

        // 計算 IPv4 Header Checksum
        var sum = 0
        for (i in 0 until 20 step 2) {
            val word = ((response[i].toInt() and 0xFF) shl 8) or (response[i + 1].toInt() and 0xFF)
            sum += word
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        response[10] = ((checksum ushr 8) and 0xFF).toByte()
        response[11] = (checksum and 0xFF).toByte()

        // --- UDP Header (8 bytes) ---
        response[20] = requestPacket[reqIpHeaderLen + 2]
        response[21] = requestPacket[reqIpHeaderLen + 3]
        response[22] = requestPacket[reqIpHeaderLen]
        response[23] = requestPacket[reqIpHeaderLen + 1]

        val udpLen = 8 + dnsPayload.size
        response[24] = ((udpLen ushr 8) and 0xFF).toByte()
        response[25] = (udpLen and 0xFF).toByte()

        response[26] = 0
        response[27] = 0

        // --- DNS Payload ---
        System.arraycopy(dnsPayload, 0, response, 28, dnsPayload.size)

        return response
    }
}
