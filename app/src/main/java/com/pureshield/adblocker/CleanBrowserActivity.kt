package com.pureshield.adblocker

import android.annotation.SuppressLint
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.ByteArrayInputStream

class CleanBrowserActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var etUrl: EditText
    private lateinit var progressBar: ProgressBar
    private lateinit var tvPageBlockedCount: TextView
    private var pageBlocked = 0

    private val COSMETIC_AD_HIDE_JS = """
        (function() {
            var styleId = 'pureshield-cosmetic-css';
            if (!document.getElementById(styleId)) {
                var style = document.createElement('style');
                style.id = styleId;
                style.innerHTML = `
                    ins.adsbygoogle,
                    .adsbygoogle,
                    [id^="google_ads_iframe"],
                    [id^="div-gpt-ad"],
                    [class*="ad-container"],
                    [class*="ad-wrapper"],
                    [class*="ad-banner"],
                    [id*="taboola"],
                    [class*="taboola"],
                    [id*="outbrain"],
                    [class*="outbrain"],
                    .onead-container,
                    #onead-container,
                    .popinRecommend,
                    #_popIn_recommend,
                    .dable-widget,
                    iframe[src*="doubleclick.net"],
                    iframe[src*="googlesyndication.com"] {
                        display: none !important;
                        height: 0 !important;
                        min-height: 0 !important;
                        margin: 0 !important;
                        padding: 0 !important;
                        visibility: hidden !important;
                        pointer-events: none !important;
                    }
                `;
                document.head.appendChild(style);
            }
        })();
    """.trimIndent()

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_clean_browser)

        BlocklistManager.init(applicationContext)

        webView = findViewById(R.id.webView)
        etUrl = findViewById(R.id.etUrl)
        progressBar = findViewById(R.id.progressBar)
        tvPageBlockedCount = findViewById(R.id.tvPageBlockedCount)

        findViewById<ImageButton>(R.id.btnBackHome).setOnClickListener {
            finish()
        }

        findViewById<ImageButton>(R.id.btnReload).setOnClickListener {
            webView.reload()
        }

        etUrl.setOnEditorActionListener { _, actionId, event ->
            if (actionId == EditorInfo.IME_ACTION_GO ||
                (event != null && event.keyCode == KeyEvent.KEYCODE_ENTER && event.action == KeyEvent.ACTION_DOWN)
            ) {
                loadUserInput(etUrl.text.toString())
                true
            } else {
                false
            }
        }

        setupWebView()

        val sharedText = intent?.getStringExtra(Intent.EXTRA_TEXT)
        val initialUrl = extractUrl(sharedText) ?: "https://www.google.com.tw"
        loadUserInput(initialUrl)
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            setSupportMultipleWindows(true)
            javaScriptCanOpenWindowsAutomatically = false
            mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
            useWideViewPort = true
            loadWithOverviewMode = true
            builtInZoomControls = true
            displayZoomControls = false
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                if (newProgress < 100) {
                    progressBar.visibility = View.VISIBLE
                    progressBar.progress = newProgress
                } else {
                    progressBar.visibility = View.GONE
                    view?.evaluateJavascript(COSMETIC_AD_HIDE_JS, null)
                }
            }

            override fun onCreateWindow(
                view: WebView?,
                isDialog: Boolean,
                isUserGesture: Boolean,
                resultMsg: android.os.Message?
            ): Boolean {
                return false
            }
        }

        webView.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                super.onPageStarted(view, url, favicon)
                pageBlocked = 0
                updateBadge()
                url?.let { etUrl.setText(it) }
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                super.onPageFinished(view, url)
                view?.evaluateJavascript(COSMETIC_AD_HIDE_JS, null)
            }

            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest?
            ): WebResourceResponse? {
                val host = request?.url?.host ?: return super.shouldInterceptRequest(view, request)
                if (BlocklistManager.shouldBlock(host)) {
                    pageBlocked++
                    BlocklistManager.recordQuery(applicationContext, host, true)
                    runOnUiThread { updateBadge() }
                    return WebResourceResponse(
                        "text/plain",
                        "UTF-8",
                        ByteArrayInputStream(ByteArray(0))
                    )
                }
                return super.shouldInterceptRequest(view, request)
            }
        }
    }

    private fun updateBadge() {
        tvPageBlockedCount.text = "本頁已消滅 $pageBlocked 個廣告"
    }

    private fun loadUserInput(rawInput: String) {
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) return
        val targetUrl = if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            trimmed
        } else if (trimmed.contains('.') && !trimmed.contains(' ')) {
            "https://$trimmed"
        } else {
            "https://www.google.com.tw/search?q=${android.net.Uri.encode(trimmed)}"
        }
        etUrl.setText(targetUrl)
        webView.loadUrl(targetUrl)
    }

    private fun extractUrl(text: String?): String? {
        if (text.isNullOrBlank()) return null
        val regex = Regex("(https?://[^\\s]+)")
        return regex.find(text)?.value
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
}
