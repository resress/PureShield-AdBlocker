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
import android.widget.ArrayAdapter
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
    private lateinit var lvDnsLogs: ListView

    private val logDisplayList = ArrayList<String>()
    private val logDomainList = ArrayList<BlocklistManager.DnsLogItem>()
    private lateinit var logAdapter: ArrayAdapter<String>

    private val uiHandler = Handler(Looper.getMainLooper())
    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshDashboardUi()
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
        refreshDashboardUi()
    }

    private fun bindViews() {
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
        lvDnsLogs = findViewById(R.id.lvDnsLogs)

        logAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_list_item_1,
            logDisplayList
        )
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
            btnUpdateCloud.text = "正在同步規則庫..."
            lifecycleScope.launch {
                val res = BlocklistManager.updateCloudBlocklist(applicationContext)
                btnUpdateCloud.isEnabled = true
                btnUpdateCloud.text = "雲端擴充規則庫"
                res.onSuccess { total ->
                    Toast.makeText(
                        this@MainActivity,
                        "規則庫更新成功！目前已載入 $total 筆廣告根網域",
                        Toast.LENGTH_LONG
                    ).show()
                    refreshDashboardUi()
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

        lvDnsLogs.setOnItemClickListener { _, _, position, _ ->
            if (position in logDomainList.indices) {
                val item = logDomainList[position]
                showQuickRuleActionDialog(item.domain, item.blocked)
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
        uiHandler.postDelayed({ refreshDashboardUi() }, 300)
    }

    private fun stopAdBlockService() {
        val intent = Intent(this, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_STOP
        }
        startService(intent)
        uiHandler.postDelayed({ refreshDashboardUi() }, 300)
    }

    private fun refreshDashboardUi() {
        val running = AdBlockVpnService.isRunning
        if (running) {
            tvStatusBadge.text = "🛡️ 系統級 DNS 廣告防護：運作中"
            tvStatusBadge.setTextColor(Color.parseColor("#34D399"))
            tvStatusSubtitle.text = "正在背景過濾 Chrome 與各瀏覽器的廣告網域請求（零降速模式）"
            btnToggleVpn.text = "停止廣告攔截防護"
            btnToggleVpn.setBackgroundColor(Color.parseColor("#EF4444"))
        } else {
            tvStatusBadge.text = "⚪ 系統級 DNS 廣告防護：未啟動"
            tvStatusBadge.setTextColor(Color.parseColor("#9CA3AF"))
            tvStatusSubtitle.text = "點擊下方按鈕即可啟動本機防護，不耗電且不影響一般網速"
            btnToggleVpn.text = "立即啟動廣告攔截"
            btnToggleVpn.setBackgroundColor(Color.parseColor("#10B981"))
        }

        tvSessionBlocked.text = BlocklistManager.sessionBlockedCount.get().toString()
        tvTotalBlocked.text = BlocklistManager.totalBlockedCount.get().toString()
        tvRulesCount.text = "${BlocklistManager.getTotalRulesCount()} 筆根網域 (含全子網域)"
        tvLastUpdate.text = "規則庫狀態：${BlocklistManager.getLastUpdateTime(this)}"

        logDisplayList.clear()
        logDomainList.clear()
        val snapshot = BlocklistManager.recentLogs.toList()
        for (item in snapshot) {
            logDomainList.add(item)
            val tag = if (item.blocked) "🚫 [已擋廣告]" else "✅ [正常放行]"
            logDisplayList.add("${item.time}  $tag  ${item.domain}")
        }
        logAdapter.notifyDataSetChanged()
    }

    private fun showQuickRuleActionDialog(domain: String, currentlyBlocked: Boolean) {
        val statusText = if (currentlyBlocked) "目前狀態：已攔截封鎖" else "目前狀態：正常放行"
        val options = arrayOf(
            "🚫 加入黑名單（強制阻擋 $domain）",
            "✅ 加入白名單（永遠放行 $domain）",
            "🗑️ 移除自訂規則（恢復預設判斷）"
        )
        AlertDialog.Builder(this)
            .setTitle(domain)
            .setSingleChoiceItems(options, -1) { dialog, which ->
                when (which) {
                    0 -> {
                        BlocklistManager.addUserBlacklist(this, domain)
                        Toast.makeText(this, "已將 $domain 加入自訂黑名單", Toast.LENGTH_SHORT).show()
                    }
                    1 -> {
                        BlocklistManager.addUserWhitelist(this, domain)
                        Toast.makeText(this, "已將 $domain 加入白名單", Toast.LENGTH_SHORT).show()
                    }
                    2 -> {
                        BlocklistManager.removeUserRule(this, domain)
                        Toast.makeText(this, "已移除 $domain 的自訂設定", Toast.LENGTH_SHORT).show()
                    }
                }
                refreshDashboardUi()
                dialog.dismiss()
            }
            .setNeutralButton(statusText, null)
            .setNegativeButton("取消", null)
            .show()
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

        val blackListStr = BlocklistManager.getUserBlacklist().joinToString(", ").ifEmpty { "無" }
        val whiteListStr = BlocklistManager.getUserWhitelist().joinToString(", ").ifEmpty { "無" }

        val infoView = TextView(this).apply {
            text = "\n📌 自訂黑名單：$blackListStr\n\n📌 自訂白名單：$whiteListStr"
            textSize = 13f
            setPadding(0, 16, 0, 0)
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
                    refreshDashboardUi()
                }
            }
            .setNeutralButton("加入白名單") { _, _ ->
                val text = input.text.toString()
                if (text.isNotBlank()) {
                    BlocklistManager.addUserWhitelist(this, text)
                    Toast.makeText(this, "已新增至白名單", Toast.LENGTH_SHORT).show()
                    refreshDashboardUi()
                }
            }
            .setNegativeButton("關閉", null)
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
}
