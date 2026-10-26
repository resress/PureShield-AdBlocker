package com.pureshield.adblocker

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var topDashboardContainer: LinearLayout
    private lateinit var tvStatusBadge: TextView
    private lateinit var tvStatusSubtitle: TextView
    private lateinit var btnToggleVpn: Button
    private lateinit var tvSessionBlocked: TextView
    private lateinit var tvTotalBlocked: TextView
    private lateinit var tvRulesCount: TextView
    private lateinit var tvLastUpdate: TextView
    private lateinit var btnUpdateCloud: Button
    private lateinit var btnCustomRules: Button
    private lateinit var btnChromeGuide: Button
    private lateinit var btnOpenCleanBrowser: Button

    private lateinit var tvLogSectionTitle: TextView
    private lateinit var btnFilterBlocked: Button
    private lateinit var btnPauseLog: Button
    private lateinit var btnExpandLog: Button
    private lateinit var tvEmptyLogHint: TextView
    private lateinit var lvDnsLogs: ListView

    private val displayedLogs = ArrayList<BlocklistManager.DnsLogItem>()
    private lateinit var logAdapter: DnsLogAdapter

    private var filterBlockedOnly = false
    private var isLogPaused = false
    private var isLogFullScreen = false
    private var lastRenderedTopLogId: Long = -1L
    private var lastRenderedSize: Int = -1

    private val uiHandler = Handler(Looper.getMainLooper())
    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshDashboardUi(forceLogRefresh = false)
            uiHandler.postDelayed(this, 1000)
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startAdBlockService()
        } else {
            Toast.makeText(this, "需要允許 VPN 權限才能在背景為瀏覽器攔截廣告", Toast.LENGTH_LONG).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        prepareAndStartVpn()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        BlocklistManager.init(applicationContext)

        bindViews()
        setupListeners()
        refreshDashboardUi(forceLogRefresh = true)
    }

    private fun bindViews() {
        topDashboardContainer = findViewById(R.id.topDashboardContainer)
        tvStatusBadge = findViewById(R.id.tvStatusBadge)
        tvStatusSubtitle = findViewById(R.id.tvStatusSubtitle)
        btnToggleVpn = findViewById(R.id.btnToggleVpn)
        tvSessionBlocked = findViewById(R.id.tvSessionBlocked)
        tvTotalBlocked = findViewById(R.id.tvTotalBlocked)
        tvRulesCount = findViewById(R.id.tvRulesCount)
        tvLastUpdate = findViewById(R.id.tvLastUpdate)
        btnUpdateCloud = findViewById(R.id.btnUpdateCloud)
        btnCustomRules = findViewById(R.id.btnCustomRules)
        btnChromeGuide = findViewById(R.id.btnChromeGuide)
        btnOpenCleanBrowser = findViewById(R.id.btnOpenCleanBrowser)

        tvLogSectionTitle = findViewById(R.id.tvLogSectionTitle)
        btnFilterBlocked = findViewById(R.id.btnFilterBlocked)
        btnPauseLog = findViewById(R.id.btnPauseLog)
        btnExpandLog = findViewById(R.id.btnExpandLog)
        tvEmptyLogHint = findViewById(R.id.tvEmptyLogHint)
        lvDnsLogs = findViewById(R.id.lvDnsLogs)

        logAdapter = DnsLogAdapter(this, displayedLogs)
        lvDnsLogs.adapter = logAdapter
    }

    private fun setupListeners() {
        btnToggleVpn.setOnClickListener {
            if (AdBlockVpnService.isRunning) {
                stopAdBlockService()
            } else {
                checkNotificationAndStartVpn()
            }
        }

        btnUpdateCloud.setOnClickListener {
            btnUpdateCloud.isEnabled = false
            btnUpdateCloud.text = "同步中..."
            lifecycleScope.launch {
                val res = BlocklistManager.updateCloudBlocklist(applicationContext)
                btnUpdateCloud.isEnabled = true
                btnUpdateCloud.text = "雲端更新"
                res.onSuccess { total ->
                    Toast.makeText(
                        this@MainActivity,
                        "規則庫更新成功！目前已載入 $total 筆廣告根網域",
                        Toast.LENGTH_LONG
                    ).show()
                    refreshDashboardUi(forceLogRefresh = true)
                }.onFailure { err ->
                    Toast.makeText(
                        this@MainActivity,
                        "更新失敗：${err.message}",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }

        btnCustomRules.setOnClickListener {
            showCustomRulesDialog()
        }

        btnChromeGuide.setOnClickListener {
            showChromeSetupGuideDialog()
        }

        btnOpenCleanBrowser.setOnClickListener {
            startActivity(Intent(this, CleanBrowserActivity::class.java))
        }

        btnFilterBlocked.setOnClickListener {
            filterBlockedOnly = !filterBlockedOnly
            if (filterBlockedOnly) {
                btnFilterBlocked.text = "🚫只看攔截"
                btnFilterBlocked.setBackgroundColor(Color.parseColor("#DC2626"))
            } else {
                btnFilterBlocked.text = "全部顯示"
                btnFilterBlocked.setBackgroundColor(Color.parseColor("#334155"))
            }
            refreshDashboardUi(forceLogRefresh = true)
        }

        btnPauseLog.setOnClickListener {
            isLogPaused = !isLogPaused
            if (isLogPaused) {
                btnPauseLog.text = "▶️ 繼續"
                btnPauseLog.setBackgroundColor(Color.parseColor("#D97706"))
                Toast.makeText(this, "已暫停日誌刷新，可安心滑動查看詳細資料", Toast.LENGTH_SHORT).show()
            } else {
                btnPauseLog.text = "⏸️ 暫停"
                btnPauseLog.setBackgroundColor(Color.parseColor("#334155"))
                refreshDashboardUi(forceLogRefresh = true)
            }
        }

        btnExpandLog.setOnClickListener {
            isLogFullScreen = !isLogFullScreen
            if (isLogFullScreen) {
                topDashboardContainer.visibility = View.GONE
                btnExpandLog.text = "🔽 顯示面板"
                btnExpandLog.setBackgroundColor(Color.parseColor("#475569"))
            } else {
                topDashboardContainer.visibility = View.VISIBLE
                btnExpandLog.text = "🔍 全螢幕"
                btnExpandLog.setBackgroundColor(Color.parseColor("#0284C7"))
            }
        }

        lvDnsLogs.setOnItemClickListener { _, _, position, _ ->
            if (position in displayedLogs.indices) {
                val item = displayedLogs[position]
                showDomainDetailDialog(item)
            }
        }
    }

    private fun checkNotificationAndStartVpn() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        prepareAndStartVpn()
    }

    private fun prepareAndStartVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startAdBlockService()
        }
    }

    private fun startAdBlockService() {
        val intent = Intent(this, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        uiHandler.postDelayed({ refreshDashboardUi(forceLogRefresh = true) }, 300)
    }

    private fun stopAdBlockService() {
        val intent = Intent(this, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_STOP
        }
        startService(intent)
        uiHandler.postDelayed({ refreshDashboardUi(forceLogRefresh = true) }, 300)
    }

    private fun refreshDashboardUi(forceLogRefresh: Boolean) {
        val running = AdBlockVpnService.isRunning
        if (running) {
            tvStatusBadge.text = "🛡️ 系統級 DNS 防護：運作中"
            tvStatusBadge.setTextColor(Color.parseColor("#34D399"))
            tvStatusSubtitle.text = "正在背景過濾 Chrome 與各瀏覽器的廣告網域請求（零降速模式）"
            btnToggleVpn.text = "停止防護"
            btnToggleVpn.setBackgroundColor(Color.parseColor("#EF4444"))
        } else {
            tvStatusBadge.text = "⚪ 系統級 DNS 防護：未啟動"
            tvStatusBadge.setTextColor(Color.parseColor("#9CA3AF"))
            tvStatusSubtitle.text = "點擊右側按鈕即可啟動本機防護，不耗電且不影響網速"
            btnToggleVpn.text = "啟動防護"
            btnToggleVpn.setBackgroundColor(Color.parseColor("#10B981"))
        }

        tvSessionBlocked.text = BlocklistManager.sessionBlockedCount.get().toString()
        tvTotalBlocked.text = BlocklistManager.totalBlockedCount.get().toString()
        tvRulesCount.text = BlocklistManager.getTotalRulesCount().toString()
        tvLastUpdate.text = "規則庫狀態：${BlocklistManager.getLastUpdateTime(this)}"

        if (isLogPaused && !forceLogRefresh) {
            return
        }

        val snapshot = BlocklistManager.recentLogs.toList()
        val filtered = if (filterBlockedOnly) {
            snapshot.filter { it.blocked }
        } else {
            snapshot
        }

        tvLogSectionTitle.text = "📡 網域監控日誌 (${filtered.size} 筆 · 點擊看詳情)"

        if (filtered.isEmpty()) {
            tvEmptyLogHint.visibility = View.VISIBLE
            lvDnsLogs.visibility = View.GONE
            tvEmptyLogHint.text = if (filterBlockedOnly) {
                "目前尚無「已攔截廣告」的紀錄。\n您可切換為「全部顯示」查看所有網域請求，或開啟瀏覽器逛逛新聞網站。"
            } else {
                "目前尚無網域紀錄。\n請先點擊上方「啟動防護」，接著打開手機瀏覽器瀏覽網頁，這裡就會即時列出每一筆網域與攔截詳細原因！"
            }
            displayedLogs.clear()
            logAdapter.notifyDataSetChanged()
            lastRenderedTopLogId = -1L
            lastRenderedSize = 0
            return
        }

        tvEmptyLogHint.visibility = View.GONE
        lvDnsLogs.visibility = View.VISIBLE

        val currentTopId = filtered.first().id
        if (!forceLogRefresh && currentTopId == lastRenderedTopLogId && filtered.size == lastRenderedSize) {
            return
        }

        lastRenderedTopLogId = currentTopId
        lastRenderedSize = filtered.size

        displayedLogs.clear()
        displayedLogs.addAll(filtered)
        logAdapter.notifyDataSetChanged()
    }

    private fun showDomainDetailDialog(item: BlocklistManager.DnsLogItem) {
        val rootDomain = BlocklistManager.extractRootDomain(item.domain)
        val latestCheck = BlocklistManager.checkDomain(item.domain)
        val statusIcon = if (latestCheck.blocked) "🚫 已攔截阻斷 (NXDOMAIN)" else "✅ 正常放行"

        val detailContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(52, 28, 52, 12)
        }

        val detailText = """
            🕒 發生時間：${item.time}
            📡 查詢類型：${item.qTypeStr}
            
            🌐 完整請求網域：
            ${item.domain}
            
            🏠 所屬根網域 (主網域)：
            $rootDomain
            
            🛡️ 目前判定狀態：
            $statusIcon
            
            📌 詳細命中規則與說明：
            ${latestCheck.reasonDetail}
        """.trimIndent()

        val tvDetails = TextView(this).apply {
            text = detailText
            textSize = 13.5f
            setTextColor(Color.parseColor("#E2E8F0"))
            setBackgroundColor(Color.parseColor("#1E293B"))
            setPadding(32, 28, 32, 28)
            setTextIsSelectable(true)
        }
        detailContainer.addView(tvDetails)

        val actionHint = TextView(this).apply {
            text = "\n👇 請選擇要對此網域執行的規則操作："
            textSize = 13f
            setTextColor(Color.parseColor("#38BDF8"))
            setPadding(4, 12, 4, 8)
        }
        detailContainer.addView(actionHint)

        val actions = arrayOf(
            "🚫 封鎖此完整網域 (${item.domain})",
            "🚫 封鎖整個根網域 (*.$rootDomain)",
            "✅ 白名單放行此網域 (${item.domain})",
            "✅ 白名單放行整個根網域 (*.$rootDomain)",
            "📋 複製完整網域名稱",
            "🗑️ 移除自訂規則（恢復預設判斷）"
        )

        val listView = ListView(this).apply {
            adapter = android.widget.ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_list_item_1,
                actions
            )
        }
        detailContainer.addView(listView)

        val dialog = AlertDialog.Builder(this)
            .setTitle("📊 網域請求詳細資料")
            .setView(detailContainer)
            .setNegativeButton("關閉", null)
            .create()

        listView.setOnItemClickListener { _, _, which, _ ->
            when (which) {
                0 -> {
                    BlocklistManager.addUserBlacklist(this, item.domain)
                    Toast.makeText(this, "已封鎖：${item.domain}", Toast.LENGTH_SHORT).show()
                }
                1 -> {
                    BlocklistManager.addUserBlacklist(this, rootDomain)
                    Toast.makeText(this, "已封鎖整個根網域：*.$rootDomain", Toast.LENGTH_SHORT).show()
                }
                2 -> {
                    BlocklistManager.addUserWhitelist(this, item.domain)
                    Toast.makeText(this, "已加入白名單放行：${item.domain}", Toast.LENGTH_SHORT).show()
                }
                3 -> {
                    BlocklistManager.addUserWhitelist(this, rootDomain)
                    Toast.makeText(this, "已放行整個根網域：*.$rootDomain", Toast.LENGTH_SHORT).show()
                }
                4 -> {
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("domain", item.domain))
                    Toast.makeText(this, "已複製：${item.domain}", Toast.LENGTH_SHORT).show()
                }
                5 -> {
                    BlocklistManager.removeUserRule(this, item.domain)
                    BlocklistManager.removeUserRule(this, rootDomain)
                    Toast.makeText(this, "已移除自訂設定，恢復預設規則", Toast.LENGTH_SHORT).show()
                }
            }
            refreshDashboardUi(forceLogRefresh = true)
            dialog.dismiss()
        }

        dialog.show()
    }

    private fun showCustomRulesDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(56, 36, 56, 16)
        }

        val input = EditText(this).apply {
            hint = "輸入網域，例如：ads.example.com"
            inputType = InputType.TYPE_TEXT_VARIATION_URI
        }
        layout.addView(input)

        val blackListStr = BlocklistManager.getUserBlacklist().joinToString("\n• ").let {
            if (it.isEmpty()) "無" else "\n• $it"
        }
        val whiteListStr = BlocklistManager.getUserWhitelist().joinToString("\n• ").let {
            if (it.isEmpty()) "無" else "\n• $it"
        }

        val infoView = TextView(this).apply {
            text = "\n📌 自訂黑名單：$blackListStr\n\n📌 自訂白名單：$whiteListStr"
            textSize = 13f
            setPadding(0, 16, 0, 0)
            setTextIsSelectable(true)
        }
        layout.addView(infoView)

        AlertDialog.Builder(this)
            .setTitle("管理自訂黑白名單")
            .setView(layout)
            .setPositiveButton("加入黑名單") { _, _ ->
                val text = input.text.toString()
                if (text.isNotBlank()) {
                    BlocklistManager.addUserBlacklist(this, text)
                    Toast.makeText(this, "已新增至黑名單", Toast.LENGTH_SHORT).show()
                    refreshDashboardUi(forceLogRefresh = true)
                }
            }
            .setNeutralButton("加入白名單") { _, _ ->
                val text = input.text.toString()
                if (text.isNotBlank()) {
                    BlocklistManager.addUserWhitelist(this, text)
                    Toast.makeText(this, "已新增至白名單", Toast.LENGTH_SHORT).show()
                    refreshDashboardUi(forceLogRefresh = true)
                }
            }
            .setNegativeButton("清空日誌") { _, _ ->
                BlocklistManager.clearLogs()
                refreshDashboardUi(forceLogRefresh = true)
                Toast.makeText(this, "已清空監控日誌", Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    private fun showChromeSetupGuideDialog() {
        val message = """
            為了讓手機上的 Chrome 瀏覽器 100% 經過本軟體的 DNS 廣告過濾，建議確認以下兩個小設定：

            【步驟 1：關閉 Chrome 內建安全 DNS (DoH)】
            1. 打開 Chrome 右上角「⋮」→「設定」
            2. 點選「隱私權和安全性」→「使用安全 DNS」
            3. 將「使用安全 DNS」設為【關閉】（或選擇「使用目前的服務供應商」）。
            （原因：若 Chrome 強制使用 Google 加密 DNS，會繞過手機系統的 VPN 攔截通道）

            【步驟 2：清除 Chrome DNS 快取（選用）】
            在 Chrome 網址列貼上：
            chrome://net-internals/#dns
            點擊「Clear host cache」即可立即對已開過的網站生效！
        """.trimIndent()

        AlertDialog.Builder(this)
            .setTitle("💡 讓 Chrome 擋廣告 100% 生效秘訣")
            .setMessage(message)
            .setPositiveButton("複製清快取網址") { _, _ ->
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("chrome_dns", "chrome://net-internals/#dns"))
                Toast.makeText(this, "已複製 chrome://net-internals/#dns，可貼至 Chrome 網址列", Toast.LENGTH_LONG).show()
            }
            .setNegativeButton("我知道了", null)
            .show()
    }

    override fun onResume() {
        super.onResume()
        uiHandler.post(refreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        uiHandler.removeCallbacks(refreshRunnable)
    }

    private class DnsLogAdapter(
        context: Context,
        private val items: List<BlocklistManager.DnsLogItem>
    ) : BaseAdapter() {

        private val inflater = LayoutInflater.from(context)

        override fun getCount(): Int = items.size
        override fun getItem(position: Int): Any = items[position]
        override fun getItemId(position: Int): Long = items[position].id

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val holder: ViewHolder
            val view: View
            if (convertView == null) {
                view = inflater.inflate(R.layout.item_dns_log, parent, false)
                holder = ViewHolder(
                    tvStatusBadge = view.findViewById(R.id.tvLogStatusBadge),
                    tvQType = view.findViewById(R.id.tvLogQType),
                    tvTime = view.findViewById(R.id.tvLogTime),
                    tvDomain = view.findViewById(R.id.tvLogDomain),
                    tvReason = view.findViewById(R.id.tvLogReason)
                )
                view.tag = holder
            } else {
                view = convertView
                holder = view.tag as ViewHolder
            }

            val item = items[position]
            if (item.blocked) {
                holder.tvStatusBadge.text = "🚫 已攔截廣告"
                holder.tvStatusBadge.setBackgroundColor(Color.parseColor("#DC2626"))
                holder.tvDomain.setTextColor(Color.parseColor("#FCA5A5"))
                holder.tvReason.setTextColor(Color.parseColor("#F87171"))
            } else {
                holder.tvStatusBadge.text = "✅ 正常放行"
                holder.tvStatusBadge.setBackgroundColor(Color.parseColor("#059669"))
                holder.tvDomain.setTextColor(Color.parseColor("#F8FAFC"))
                holder.tvReason.setTextColor(Color.parseColor("#94A3B8"))
            }

            holder.tvQType.text = item.qTypeStr
            holder.tvTime.text = "${item.time} · 點擊詳情 ❯"
            holder.tvDomain.text = item.domain
            holder.tvReason.text = "📌 ${item.reasonDetail}"

            return view
        }

        private class ViewHolder(
            val tvStatusBadge: TextView,
            val tvQType: TextView,
            val tvTime: TextView,
            val tvDomain: TextView,
            val tvReason: TextView
        )
    }
}
