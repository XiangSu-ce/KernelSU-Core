package dawang.KernelSU.Core.ui.screen

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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
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
import dawang.KernelSU.Core.ui.navigation3.Navigator
import dawang.KernelSU.Core.ui.theme.RazerColors
import dawang.KernelSU.Core.ui.util.execKsud
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
    navigator: Navigator,
    bottomInnerPadding: Dp
) {
    val scrollBehavior = MiuixScrollBehavior()
    val hazeState = remember { HazeState() }
    val hazeStyle = HazeStyle(
        backgroundColor = colorScheme.surface,
        tint = HazeTint(colorScheme.surface.copy(0.8f))
    )

    val isKsuValid = Natives.isManager && (Natives.version > 0)

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
                    color = RazerColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    StealthSwitch(
                        featureId = Natives.FEATURE_PROP_SPOOF,
                        titleRes = R.string.stealth_prop_spoof,
                        summaryRes = R.string.stealth_prop_spoof_summary,
                        icon = Icons.Rounded.Fingerprint,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_PROC_HIDE,
                        titleRes = R.string.stealth_proc_hide,
                        summaryRes = R.string.stealth_proc_hide_summary,
                        icon = Icons.Rounded.VisibilityOff,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_SYMBOL_HIDE,
                        titleRes = R.string.stealth_symbol_hide,
                        summaryRes = R.string.stealth_symbol_hide_summary,
                        icon = Icons.Rounded.Code,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_MOUNT_SANITIZE,
                        titleRes = R.string.stealth_mount_sanitize,
                        summaryRes = R.string.stealth_mount_sanitize_summary,
                        icon = Icons.Rounded.Layers,
                        isKsuValid = isKsuValid,
                    )
                }

                // ══ 痕迹消除 ══
                Text(
                    text = stringResource(R.string.stealth_section_trace),
                    modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 4.dp),
                    color = RazerColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    StealthSwitch(
                        featureId = Natives.FEATURE_DEBUG_DISABLE,
                        titleRes = R.string.stealth_debug_disable,
                        summaryRes = R.string.stealth_debug_disable_summary,
                        icon = Icons.Rounded.Block,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_LOG_SILENT,
                        titleRes = R.string.stealth_log_silent,
                        summaryRes = R.string.stealth_log_silent_summary,
                        icon = Icons.Rounded.VolumeOff,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_FILTER_IO,
                        titleRes = R.string.stealth_filter_io,
                        summaryRes = R.string.stealth_filter_io_summary,
                        icon = Icons.Rounded.FilterList,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_FILEIO,
                        titleRes = R.string.stealth_fileio,
                        summaryRes = R.string.stealth_fileio_summary,
                        icon = Icons.Rounded.Description,
                        isKsuValid = isKsuValid,
                    )
                }

                // ══ 高级隐匿 ══
                Text(
                    text = stringResource(R.string.stealth_section_advanced),
                    modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 4.dp),
                    color = RazerColors.GreenDim,
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
                        titleRes = R.string.stealth_modloader,
                        summaryRes = R.string.stealth_modloader_summary,
                        icon = Icons.Rounded.Memory,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_EXEC,
                        titleRes = R.string.stealth_exec,
                        summaryRes = R.string.stealth_exec_summary,
                        icon = Icons.Rounded.PlayArrow,
                        isKsuValid = isKsuValid,
                    )
                    StealthSwitch(
                        featureId = Natives.FEATURE_STEALTH_IPC,
                        titleRes = R.string.stealth_ipc,
                        summaryRes = R.string.stealth_ipc_summary,
                        icon = Icons.Rounded.Share,
                        isKsuValid = isKsuValid,
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
    titleRes: Int,
    summaryRes: Int,
    icon: ImageVector,
    isKsuValid: Boolean,
) {
    val supported = remember(featureId, isKsuValid) {
        if (isKsuValid) Natives.isFeatureSupported(featureId) else false
    }
    var enabled by rememberSaveable(featureId) {
        mutableStateOf(if (isKsuValid && supported) Natives.isFeatureEnabled(featureId) else true)
    }

    val canToggle = isKsuValid && supported

    val summary = when {
        !isKsuValid -> stringResource(R.string.stealth_not_installed_summary)
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
                tint = if (canToggle) RazerColors.GreenDim else RazerColors.T40
            )
        },
        enabled = canToggle,
        checked = enabled,
        onCheckedChange = { checked ->
            if (Natives.setFeatureEnabled(featureId, checked)) {
                execKsud("feature save", true)
                enabled = checked
            }
        }
    )
}
