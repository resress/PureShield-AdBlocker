package com.pureshield.adblocker

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

object BlocklistManager {

    private const val PREFS_NAME = "pureshield_prefs"
    private const val KEY_USER_BLACKLIST = "user_blacklist"
    private const val KEY_USER_WHITELIST = "user_whitelist"
    private const val KEY_TOTAL_BLOCKED = "total_blocked_count"
    private const val KEY_LAST_UPDATE = "last_cloud_update"
    private const val CLOUD_CACHE_FILE = "cloud_hosts_cache.txt"

    data class CheckResult(
        val blocked: Boolean,
        val matchedRule: String,
        val reasonDetail: String
    )

    data class DnsLogItem(
        val id: Long,
        val time: String,
        val domain: String,
        val qTypeStr: String,
        val blocked: Boolean,
        val matchedRule: String,
        val reasonDetail: String
    )

    private val logIdGenerator = AtomicLong(1)

    private val blockedDomains = ConcurrentHashMap.newKeySet<String>()
    private val userBlacklist = ConcurrentHashMap.newKeySet<String>()
    private val userWhitelist = ConcurrentHashMap.newKeySet<String>()

    val sessionBlockedCount = AtomicInteger(0)
    val totalBlockedCount = AtomicInteger(0)
    val recentLogs = CopyOnWriteArrayList<DnsLogItem>()

    @Volatile
    private var isInitialized = false

    private val BUILT_IN_AD_DOMAINS = listOf(
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "adservice.google.com",
        "adservice.google.com.tw",
        "pagead2.googlesyndication.com",
        "tpc.googlesyndication.com",
        "ade.googlesyndication.com",
        "google-analytics.com",
        "googletagmanager.com",
        "googletagservices.com",
        "2mdn.net",
        "admeld.com",
        "admob.com",
        "onead.com.tw",
        "tenmax.io",
        "clickforce.com.tw",
        "doublemax.net",
        "bridgewell.com",
        "scupio.com",
        "avivid.likr.tw",
        "likr.com.tw",
        "likr.tw",
        "dable.io",
        "popin.cc",
        "innity.com",
        "innity.net",
        "aotter.net",
        "trek.aotter.net",
        "adgeek.com.tw",
        "cacafly.com",
        "tagtoo.co",
        "tagtoo.com.tw",
        "pixanalytics.com",
        "adlocus.com",
        "vpon.com",
        "urad.com.tw",
        "adbert.com.tw",
        "holmesmind.com",
        "cymetrics.io",
        "taboola.com",
        "taboolasyndication.com",
        "outbrain.com",
        "outbrainimg.com",
        "criteo.com",
        "criteo.net",
        "popads.net",
        "popcash.net",
        "propellerads.com",
        "propellerclick.com",
        "adsterra.com",
        "exoclick.com",
        "juicyads.com",
        "trafficjunky.net",
        "tsyndicate.com",
        "hilltopads.net",
        "clickadu.com",
        "ad-maven.com",
        "revcontent.com",
        "mgid.com",
        "adskeeper.co.uk",
        "rubiconproject.com",
        "pubmatic.com",
        "openx.net",
        "adnxs.com",
        "smartadserver.com",
        "media.net",
        "teads.tv",
        "adroll.com",
        "casalemedia.com",
        "indexww.com",
        "advertising.com",
        "bidswitch.net",
        "sharethrough.com",
        "triplelift.com",
        "33across.com",
        "sovrn.com",
        "lijit.com",
        "gumgum.com",
        "yieldmo.com",
        "zedo.com",
        "serving-sys.com",
        "flashtalking.com",
        "celtra.com",
        "moatads.com",
        "iasds01.com",
        "adsafeprotected.com",
        "scorecardresearch.com",
        "quantserve.com",
        "bluekai.com",
        "krxd.net",
        "demdex.net",
        "omtrdc.net",
        "everesttech.net",
        "mathtag.com",
        "rlcdn.com",
        "tapad.com",
        "agkn.com",
        "turn.com",
        "unityads.unity3d.com",
        "applovin.com",
        "applvn.com",
        "vungle.com",
        "chartboost.com",
        "inmobi.com",
        "ironsrc.com",
        "supersonicads.com",
        "startappservice.com",
        "adcolony.com",
        "fyber.com",
        "tapjoy.com",
        "pangle.io",
        "byteoversea.com",
        "mopub.com",
        "smaato.net",
        "amazon-adsystem.com",
        "aaxads.com",
        "ads-twitter.com",
        "an.facebook.com"
    )

    private val AD_SUBDOMAIN_PREFIXES = listOf(
        "ad.", "ads.", "adserver.", "adservice.", "adbanner.",
        "banner.", "banners.", "pop.", "popunder.", "telemetry.",
        "track.", "tracker.", "tracking.", "stat.", "stats.", "pixel."
    )

    fun init(context: Context) {
        if (isInitialized) return
        synchronized(this) {
            if (isInitialized) return
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            totalBlockedCount.set(prefs.getInt(KEY_TOTAL_BLOCKED, 0))

            BUILT_IN_AD_DOMAINS.forEach { blockedDomains.add(it.lowercase(Locale.ROOT)) }

            prefs.getStringSet(KEY_USER_BLACKLIST, emptySet())?.forEach {
                userBlacklist.add(it.lowercase(Locale.ROOT))
            }
            prefs.getStringSet(KEY_USER_WHITELIST, emptySet())?.forEach {
                userWhitelist.add(it.lowercase(Locale.ROOT))
            }

            loadCloudCache(context)
            isInitialized = true
        }
    }

    private fun loadCloudCache(context: Context) {
        val file = File(context.filesDir, CLOUD_CACHE_FILE)
        if (!file.exists()) return
        try {
            file.forEachLine { line ->
                val clean = line.trim().lowercase(Locale.ROOT)
                if (clean.isNotEmpty()) {
                    blockedDomains.add(clean)
                }
            }
        } catch (_: Exception) {
        }
    }

    fun checkDomain(domainRaw: String): CheckResult {
        val domain = domainRaw.lowercase(Locale.ROOT).trimEnd('.')
        if (domain.isEmpty()) {
            return CheckResult(false, "無", "空白網域")
        }

        findMatchedRule(domain, userWhitelist)?.let { rule ->
            return CheckResult(
                blocked = false,
                matchedRule = rule,
                reasonDetail = "命中自訂白名單 (*.$rule) → 強制放行"
            )
        }

        findMatchedRule(domain, userBlacklist)?.let { rule ->
            return CheckResult(
                blocked = true,
                matchedRule = rule,
                reasonDetail = "命中自訂黑名單 ($rule) → 本地 NXDOMAIN 阻斷"
            )
        }

        findMatchedRule(domain, blockedDomains)?.let { rule ->
            return CheckResult(
                blocked = true,
                matchedRule = rule,
                reasonDetail = "命中廣告規則庫 (*.$rule) → 0ms 本地阻斷"
            )
        }

        for (prefix in AD_SUBDOMAIN_PREFIXES) {
            if (domain.startsWith(prefix)) {
                return CheckResult(
                    blocked = true,
                    matchedRule = "$prefix*",
                    reasonDetail = "命中廣告特徵前綴 ($prefix*) → 0ms 本地阻斷"
                )
            }
        }

        return CheckResult(
            blocked = false,
            matchedRule = "正常網域",
            reasonDetail = "未命中廣告規則 → 正常轉發至 1.1.1.1"
        )
    }

    fun shouldBlock(domainRaw: String): Boolean = checkDomain(domainRaw).blocked

    private fun findMatchedRule(domain: String, set: Set<String>): String? {
        if (set.contains(domain)) return domain
        var current = domain
        while (true) {
            val dotIndex = current.indexOf('.')
            if (dotIndex < 0) break
            current = current.substring(dotIndex + 1)
            if (set.contains(current)) return current
        }
        return null
    }

    fun formatQType(qType: Int): String {
        return when (qType) {
            1 -> "IPv4 (A)"
            28 -> "IPv6 (AAAA)"
            5 -> "CNAME"
            65 -> "HTTPS (SVCB)"
            16 -> "TXT"
            else -> "TYPE-$qType"
        }
    }

    fun extractRootDomain(domain: String): String {
        val parts = domain.split('.')
        if (parts.size <= 2) return domain
        val twoPartTlds = setOf("com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw", "co.uk", "co.jp")
        val lastTwo = "${parts[parts.size - 2]}.${parts.last()}"
        return if (twoPartTlds.contains(lastTwo) && parts.size >= 3) {
            "${parts[parts.size - 3]}.$lastTwo"
        } else {
            lastTwo
        }
    }

    fun recordQuery(
        context: Context,
        domain: String,
        qType: Int = 1,
        checkResult: CheckResult? = null
    ) {
        val result = checkResult ?: checkDomain(domain)
        val timeStr = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val qTypeStr = if (qType == 0) "WEB-DOM" else formatQType(qType)

        val first = recentLogs.firstOrNull()
        if (first != null && first.domain == domain && first.blocked == result.blocked && first.time == timeStr) {
            return
        }

        val item = DnsLogItem(
            id = logIdGenerator.incrementAndGet(),
            time = timeStr,
            domain = domain,
            qTypeStr = qTypeStr,
            blocked = result.blocked,
            matchedRule = result.matchedRule,
            reasonDetail = result.reasonDetail
        )

        recentLogs.add(0, item)
        while (recentLogs.size > 150) {
            recentLogs.removeAt(recentLogs.size - 1)
        }

        if (result.blocked) {
            sessionBlockedCount.incrementAndGet()
            val total = totalBlockedCount.incrementAndGet()
            if (total % 5 == 0) {
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putInt(KEY_TOTAL_BLOCKED, total)
                    .apply()
            }
        }
    }

    fun clearLogs() {
        recentLogs.clear()
    }

    fun addUserBlacklist(context: Context, domainRaw: String) {
        val clean = cleanDomainInput(domainRaw)
        if (clean.isEmpty()) return
        userWhitelist.remove(clean)
        userBlacklist.add(clean)
        saveUserSets(context)
    }

    fun addUserWhitelist(context: Context, domainRaw: String) {
        val clean = cleanDomainInput(domainRaw)
        if (clean.isEmpty()) return
        userBlacklist.remove(clean)
        userWhitelist.add(clean)
        saveUserSets(context)
    }

    fun removeUserRule(context: Context, domainRaw: String) {
        val clean = cleanDomainInput(domainRaw)
        userBlacklist.remove(clean)
        userWhitelist.remove(clean)
        saveUserSets(context)
    }

    fun getUserBlacklist(): List<String> = userBlacklist.sorted()
    fun getUserWhitelist(): List<String> = userWhitelist.sorted()
    fun getTotalRulesCount(): Int = blockedDomains.size + userBlacklist.size

    fun getLastUpdateTime(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_LAST_UPDATE, "內建精選規則庫 (可點上方按鈕擴充)") ?: "內建精選規則庫"
    }

    private fun saveUserSets(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_USER_BLACKLIST, HashSet(userBlacklist))
            .putStringSet(KEY_USER_WHITELIST, HashSet(userWhitelist))
            .apply()
    }

    private fun cleanDomainInput(input: String): String {
        var s = input.trim().lowercase(Locale.ROOT)
        s = s.removePrefix("https://").removePrefix("http://")
        val slashIdx = s.indexOf('/')
        if (slashIdx >= 0) s = s.substring(0, slashIdx)
        return s.trimEnd('.')
    }

    suspend fun updateCloudBlocklist(context: Context): Result<Int> = withContext(Dispatchers.IO) {
        val urls = listOf(
            "https://adaway.org/hosts.txt",
            "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
        )
        val newDomains = HashSet<String>()

        try {
            for (urlString in urls) {
                val url = URL(urlString)
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    connectTimeout = 10000
                    readTimeout = 15000
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", "PureShield-Android-AdBlocker/1.1")
                }
                if (conn.responseCode == 200) {
                    BufferedReader(InputStreamReader(conn.inputStream)).use { reader ->
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            val trimmed = line!!.trim()
                            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                            val parts = trimmed.split(Regex("\\s+"))
                            if (parts.size >= 2) {
                                val host = parts[1].lowercase(Locale.ROOT).trim()
                                if (host != "localhost" && host != "localhost.localdomain" && host.contains('.')) {
                                    newDomains.add(host)
                                }
                            }
                        }
                    }
                }
                conn.disconnect()
            }

            if (newDomains.isNotEmpty()) {
                val cacheFile = File(context.filesDir, CLOUD_CACHE_FILE)
                cacheFile.bufferedWriter().use { writer ->
                    for (d in newDomains) {
                        writer.write(d)
                        writer.newLine()
                    }
                }
                blockedDomains.addAll(newDomains)

                val timeStr = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putString(KEY_LAST_UPDATE, "已同步 ($timeStr)")
                    .apply()

                Result.success(blockedDomains.size)
            } else {
                Result.failure(Exception("未取得額外規則，請檢查網路連線"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
