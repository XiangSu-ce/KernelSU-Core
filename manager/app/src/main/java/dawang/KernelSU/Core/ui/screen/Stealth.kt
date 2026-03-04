package dawang.KernelSU.Core.ui.screen

import android.widget.Toast
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.FilterList
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material.icons.rounded.VolumeOff
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource
import dawang.KernelSU.Core.Natives
import dawang.KernelSU.Core.R
import dawang.KernelSU.Core.ui.LocalMainPagerState
import dawang.KernelSU.Core.ui.navigation3.Navigator
import dawang.KernelSU.Core.ui.theme.CoreColors
import dawang.KernelSU.Core.ui.util.execKsud
import dawang.KernelSU.Core.ui.util.getFeatureStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.extra.SuperSwitch
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun StealthPager(
    _navigator: Navigator,
    bottomInnerPadding: Dp
) {
    val scrollBehavior = MiuixScrollBehavior()
    val hazeState = remember { HazeState() }
    val mainPagerState = LocalMainPagerState.current
    var refreshEpoch by remember { mutableIntStateOf(0) }
    val hazeStyle = HazeStyle(
        backgroundColor = colorScheme.surface,
        tint = HazeTint(colorScheme.surface.copy(0.8f))
    )

    val isKsuInstalled = Natives.version > 0
    val isManagerAuthorized = isKsuInstalled && Natives.isManager

    LaunchedEffect(mainPagerState.pagerState.currentPage) {
        if (mainPagerState.pagerState.currentPage == 2) {
            refreshEpoch++
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                modifier = Modifier.hazeEffect(hazeState) {
                    style = hazeStyle
                    blurRadius = 30.dp
                    noiseFactor = 0f
                },
                color = Color.Transparent,
                title = stringResource(R.string.stealth_title),
                scrollBehavior = scrollBehavior
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .hazeSource(state = hazeState)
                .padding(horizontal = 16.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                // ══ 身份隐藏 ══
                Text(
                    text = stringResource(R.string.stealth_section_identity),
                    modifier = Modifier.padding(start = 4.dp, top = 12.dp, bottom = 4.dp),
                    color = CoreColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    StealthSwitch(
                        featureId = Natives.FEATURE_PROP_SPOOF,
                        featureName = "prop_spoof",
                        titleRes = R.string.stealth_prop_spoof,
                        summaryRes = R.string.stealth_prop_spoof_summary,
                        icon = Icons.Rounded.Fingerprint,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_PROC_HIDE,
                        featureName = "proc_hide",
                        titleRes = R.string.stealth_proc_hide,
                        summaryRes = R.string.stealth_proc_hide_summary,
                        icon = Icons.Rounded.VisibilityOff,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_SYMBOL_HIDE,
                        featureName = "symbol_hide",
                        titleRes = R.string.stealth_symbol_hide,
                        summaryRes = R.string.stealth_symbol_hide_summary,
                        icon = Icons.Rounded.Code,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_MOUNT_SANITIZE,
                        featureName = "mount_sanitize",
                        titleRes = R.string.stealth_mount_sanitize,
                        summaryRes = R.string.stealth_mount_sanitize_summary,
                        icon = Icons.Rounded.Layers,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                }

                // ══ 痕迹消除 ══
                Text(
                    text = stringResource(R.string.stealth_section_trace),
                    modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 4.dp),
                    color = CoreColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    StealthSwitch(
                        featureId = Natives.FEATURE_DEBUG_DISABLE,
                        featureName = "debug_disable",
                        titleRes = R.string.stealth_debug_disable,
                        summaryRes = R.string.stealth_debug_disable_summary,
                        icon = Icons.Rounded.Block,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_LOG_SILENT,
                        featureName = "log_silent",
                        titleRes = R.string.stealth_log_silent,
                        summaryRes = R.string.stealth_log_silent_summary,
                        icon = Icons.Rounded.VolumeOff,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_FILTER_IO,
                        featureName = "stealth_filter_io",
                        titleRes = R.string.stealth_filter_io,
                        summaryRes = R.string.stealth_filter_io_summary,
                        icon = Icons.Rounded.FilterList,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_FILEIO,
                        featureName = "stealth_fileio",
                        titleRes = R.string.stealth_fileio,
                        summaryRes = R.string.stealth_fileio_summary,
                        icon = Icons.Rounded.Description,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                }

                // ══ 高级隐匿 ══
                Text(
                    text = stringResource(R.string.stealth_section_advanced),
                    modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 4.dp),
                    color = CoreColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier
                        .padding(bottom = 12.dp)
                        .fillMaxWidth(),
                ) {
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_MODLOADER,
                        featureName = "stealth_modloader",
                        titleRes = R.string.stealth_modloader,
                        summaryRes = R.string.stealth_modloader_summary,
                        icon = Icons.Rounded.Memory,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_EXEC,
                        featureName = "stealth_exec",
                        titleRes = R.string.stealth_exec,
                        summaryRes = R.string.stealth_exec_summary,
                        icon = Icons.Rounded.PlayArrow,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_IPC,
                        featureName = "stealth_ipc",
                        titleRes = R.string.stealth_ipc,
                        summaryRes = R.string.stealth_ipc_summary,
                        icon = Icons.Rounded.Share,
                        isKsuInstalled = isKsuInstalled,
                        isManagerAuthorized = isManagerAuthorized,
                        refreshEpoch = refreshEpoch,
                    )
                }

                Spacer(Modifier.height(bottomInnerPadding))
            }
        }
    }
}

@Composable
private fun StealthSwitch(
    featureId: Int,
    featureName: String,
    titleRes: Int,
    summaryRes: Int,
    icon: ImageVector,
    isKsuInstalled: Boolean,
    isManagerAuthorized: Boolean,
    refreshEpoch: Int,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var supported by remember(featureId) { mutableStateOf(false) }
    var managed by remember(featureId) { mutableStateOf(false) }
    var enabled by remember(featureId) { mutableStateOf(false) }
    var applying by remember(featureId) { mutableStateOf(false) }

    suspend fun loadFeatureState() {
        if (!isKsuInstalled || !isManagerAuthorized) {
            supported = false
            managed = false
            enabled = false
            return
        }
        val (newSupported, newManaged, newEnabled) = withContext(Dispatchers.IO) {
            val status = getFeatureStatus(featureName)
            val managedStatus = status == "managed"
            val featureSupported = Natives.isFeatureSupported(featureId)
            val featureEnabled = featureSupported && Natives.isFeatureEnabled(featureId)
            Triple(featureSupported, managedStatus, featureEnabled)
        }
        supported = newSupported
        managed = newManaged
        enabled = newEnabled
    }

    LaunchedEffect(featureId, featureName, isKsuInstalled, isManagerAuthorized, refreshEpoch) {
        loadFeatureState()
    }

    val canToggle = isKsuInstalled && isManagerAuthorized && supported && !managed && !applying

    val summary = when {
        !isKsuInstalled -> stringResource(R.string.stealth_not_installed_summary)
        !isManagerAuthorized -> stringResource(R.string.stealth_not_authorized_summary)
        managed -> stringResource(R.string.feature_status_managed_summary)
        !supported -> stringResource(R.string.feature_status_unsupported_summary)
        else -> stringResource(summaryRes)
    }

    SuperSwitch(
        title = stringResource(titleRes),
        summary = summary,
        startAction = {
            Icon(
                icon,
                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                contentDescription = stringResource(titleRes),
                tint = if (canToggle) CoreColors.GreenDim else CoreColors.T40
            )
        },
        enabled = canToggle,
        checked = enabled,
        onCheckedChange = { checked ->
            if (applying) return@SuperSwitch
            scope.launch {
                applying = true
                try {
                    val latestStatus = withContext(Dispatchers.IO) {
                        getFeatureStatus(featureName)
                    }
                    if (latestStatus == "managed") {
                        Toast.makeText(
                            context,
                            context.getString(R.string.feature_status_managed_summary),
                            Toast.LENGTH_SHORT
                        ).show()
                        loadFeatureState()
                        return@launch
                    }
                    if (latestStatus == "unsupported") {
                        loadFeatureState()
                        return@launch
                    }

                    val setOk = withContext(Dispatchers.IO) {
                        Natives.setFeatureEnabled(featureId, checked)
                    }
                    if (!setOk) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.operation_failed),
                            Toast.LENGTH_SHORT
                        ).show()
                        loadFeatureState()
                        return@launch
                    }

                    val saveOk = withContext(Dispatchers.IO) {
                        execKsud("feature save", true)
                    }
                    if (!saveOk) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.operation_failed),
                            Toast.LENGTH_SHORT
                        ).show()
                    }

                    if (checked && featureName == "prop_spoof") {
                        val applyOk = withContext(Dispatchers.IO) {
                            execKsud("debug apply prop-spoof", true)
                        }
                        if (!applyOk) {
                            Toast.makeText(
                                context,
                                context.getString(R.string.operation_failed),
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }

                    loadFeatureState()
                } finally {
                    applying = false
                }
            }
        }
    )
}
