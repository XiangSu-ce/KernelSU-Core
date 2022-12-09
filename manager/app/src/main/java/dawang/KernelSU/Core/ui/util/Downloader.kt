package dawang.KernelSU.Core.ui.util

import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Environment
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import dawang.KernelSU.Core.ksuApp
import dawang.KernelSU.Core.ui.util.module.LatestVersionInfo
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * @author weishu
 * @date 2023/6/22.
 */
@SuppressLint("Range")
fun download(
    url: String,
    fileName: String,
    onDownloaded: (Uri) -> Unit = {},
    onDownloading: () -> Unit = {},
    onProgress: (Int) -> Unit = {}
) {
    onDownloading()
    val mainHandler = Handler(Looper.getMainLooper())
    Thread {
        val target = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), fileName)
        try {
            ksuApp.okhttpClient.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                if (!resp.isSuccessful) throw IOException("HTTP ${resp.code}")
                val body = resp.body
                val total = body.contentLength()
                target.parentFile?.mkdirs()
                FileOutputStream(target).use { fos ->
                    val buf = ByteArray(8 * 1024)
                    var read: Int
                    var soFar = 0L
                    val source = body.byteStream()
                    while (true) {
                        read = source.read(buf)
                        if (read == -1) break
                        fos.write(buf, 0, read)
                        soFar += read
                        if (total > 0) {
                            val percent = ((soFar * 100L) / total).toInt().coerceIn(0, 100)
                            mainHandler.post {
                                onProgress(percent)
                            }
                        }
                    }
                    fos.flush()
                }
            }
            mainHandler.post {
                onDownloaded(Uri.fromFile(target))
            }
        } catch (_: Exception) {
            // ignore, keep UI state
        }
    }.start()
}

fun checkNewVersion(): LatestVersionInfo {
    if (!isNetworkAvailable(ksuApp)) return LatestVersionInfo()
    val url = "https://api.github.com/repos/XiangSu-ce/KernelSU-Core/releases/latest"
    // default null value if failed
    val defaultValue = LatestVersionInfo()
    runCatching {
        ksuApp.okhttpClient.newCall(Request.Builder().url(url).build()).execute()
            .use { response ->
                if (!response.isSuccessful) {
                    return defaultValue
                }
                val body = response.body.string()
                val json = org.json.JSONObject(body)
                val changelog = json.optString("body")

                val assets = json.getJSONArray("assets")
                for (i in 0 until assets.length()) {
                    val asset = assets.getJSONObject(i)
                    val name = asset.getString("name")
                    if (!name.endsWith(".apk")) {
                        continue
                    }

                    val regex = Regex("KernelSU_Core_(.+?)_(\\d+)")
                    val matchResult = regex.find(name) ?: continue
                    matchResult.groupValues[1]
                    val versionCode = matchResult.groupValues[2]
                        .toLongOrNull()
                        ?.coerceIn(0L, Int.MAX_VALUE.toLong())
                        ?.toInt()
                        ?: continue
                    val downloadUrl = asset.getString("browser_download_url")

                    return LatestVersionInfo(
                        versionCode,
                        downloadUrl,
                        changelog
                    )
                }

            }
    }
    return defaultValue
}

@Composable
fun DownloadListener(context: Context, onDownloaded: (Uri) -> Unit) {
    DisposableEffect(context) {
        val appContext = context
        val receiver = object : BroadcastReceiver() {
            @SuppressLint("Range")
            override fun onReceive(receiverContext: Context?, intent: Intent?) {
                val ctx = receiverContext ?: appContext
                if (intent?.action == DownloadManager.ACTION_DOWNLOAD_COMPLETE) {
                    val id = intent.getLongExtra(
                        DownloadManager.EXTRA_DOWNLOAD_ID, -1
                    )
                    val query = DownloadManager.Query().setFilterById(id)
                    val downloadManager =
                        ctx.getSystemService(Context.DOWNLOAD_SERVICE) as? DownloadManager
                            ?: return
                    downloadManager.query(query).use { cursor ->
                        if (cursor.moveToFirst()) {
                            val status = cursor.getInt(
                                cursor.getColumnIndex(DownloadManager.COLUMN_STATUS)
                            )
                            if (status == DownloadManager.STATUS_SUCCESSFUL) {
                                val uri = cursor.getString(
                                    cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI)
                                )
                                onDownloaded(uri.toUri())
                            }
                        }
                    }
                }
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE),
            ContextCompat.RECEIVER_EXPORTED
        )
        onDispose {
            context.unregisterReceiver(receiver)
        }
    }
}
