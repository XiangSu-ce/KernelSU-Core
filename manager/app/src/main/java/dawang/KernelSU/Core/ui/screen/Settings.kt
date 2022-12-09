package dawang.KernelSU.Core.ui.screen

import android.app.LocaleManager
import android.content.Context
import android.os.Build
import android.os.LocaleList
import android.os.PowerManager
import androidx.activity.compose.LocalActivity
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
import androidx.compose.material.icons.rounded.Adb
import androidx.compose.material.icons.rounded.AspectRatio
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Colorize
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.ContactPage
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.DeveloperMode
import androidx.compose.material.icons.rounded.Fence
import androidx.compose.material.icons.rounded.FolderDelete
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.RemoveCircle
import androidx.compose.material.icons.rounded.RemoveModerator
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Update
import androidx.compose.material.icons.rounded.UploadFile
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.edit
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource
import dawang.KernelSU.Core.KernelSUApplication
import dawang.KernelSU.Core.Natives
import dawang.KernelSU.Core.R
import dawang.KernelSU.Core.ui.component.ScaleDialog
import dawang.KernelSU.Core.ui.component.SendLogDialog
import dawang.KernelSU.Core.ui.component.UninstallDialog
import dawang.KernelSU.Core.ui.component.rememberLoadingDialog
import dawang.KernelSU.Core.ui.util.reboot
import dawang.KernelSU.Core.ui.navigation3.Navigator
import dawang.KernelSU.Core.ui.navigation3.Route
import dawang.KernelSU.Core.ui.theme.RazerColors
import dawang.KernelSU.Core.ui.util.execKsud
import dawang.KernelSU.Core.ui.util.getFeaturePersistValue
import dawang.KernelSU.Core.ui.util.getFeatureStatus
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Slider
import top.yukonga.miuix.kmp.basic.SliderDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.extra.SuperArrow
import top.yukonga.miuix.kmp.extra.SuperDropdown
import top.yukonga.miuix.kmp.extra.SuperSwitch
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * @author weishu
 * @date 2023/1/1.
 */
@Composable
fun SettingPager(
    navigator: Navigator,
    bottomInnerPadding: Dp
) {
    val scrollBehavior = MiuixScrollBehavior()
    val hazeState = remember { HazeState() }
    val hazeStyle = HazeStyle(
        backgroundColor = colorScheme.surface,
        tint = HazeTint(colorScheme.surface.copy(0.8f))
    )

    Scaffold(
        topBar = {
            TopAppBar(
                modifier = Modifier.hazeEffect(hazeState) {
                    style = hazeStyle
                    blurRadius = 30.dp
                    noiseFactor = 0f
                },
                color = Color.Transparent,
                title = stringResource(R.string.settings),
                scrollBehavior = scrollBehavior
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        val context = LocalContext.current
        val activity = LocalActivity.current
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

        val loadingDialog = rememberLoadingDialog()
        val showScaleDialog = rememberSaveable { mutableStateOf(false) }
        val showUninstallDialog = rememberSaveable { mutableStateOf(false) }
        val showSendLogDialog = rememberSaveable { mutableStateOf(false) }

        val isKsuValid = Natives.isManager && (Natives.version > 0)

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
                var checkUpdate by rememberSaveable {
                    mutableStateOf(prefs.getBoolean("check_update", true))
                }

                // ══ 检查更新 ══
                Card(
                    modifier = Modifier
                        .padding(top = 12.dp)
                        .fillMaxWidth(),
                ) {
                    SuperSwitch(
                        title = stringResource(id = R.string.settings_check_update),
                        summary = stringResource(id = R.string.settings_check_update_summary),
                        startAction = {
                            Icon(
                                Icons.Rounded.Update,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_check_update),
                                tint = RazerColors.GreenDim
                            )
                        },
                        checked = checkUpdate,
                        onCheckedChange = {
                            prefs.edit {
                                putBoolean("check_update", it)
                            }
                            checkUpdate = it
                        }
                    )
                    var checkModuleUpdate by rememberSaveable {
                        mutableStateOf(prefs.getBoolean("module_check_update", true))
                    }
                    val moduleUpdateSummary = if (isKsuValid) {
                        stringResource(id = R.string.settings_check_update_summary)
                    } else {
                        stringResource(id = R.string.settings_not_installed_summary)
                    }
                    SuperSwitch(
                        title = stringResource(id = R.string.settings_module_check_update),
                        summary = moduleUpdateSummary,
                        startAction = {
                            Icon(
                                Icons.Rounded.UploadFile,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_module_check_update),
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid,
                        checked = checkModuleUpdate,
                        onCheckedChange = {
                            prefs.edit {
                                putBoolean("module_check_update", it)
                            }
                            checkModuleUpdate = it
                        }
                    )
                }

                // ══ 外观 ══
                Text(
                    text = stringResource(id = R.string.settings_section_appearance),
                    modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 4.dp),
                    color = RazerColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier
                        .fillMaxWidth(),
                ) {
                    val themeItems = listOf(
                        stringResource(id = R.string.settings_theme_mode_system),
                        stringResource(id = R.string.settings_theme_mode_light),
                        stringResource(id = R.string.settings_theme_mode_dark),
                        stringResource(id = R.string.settings_theme_mode_monet_system),
                        stringResource(id = R.string.settings_theme_mode_monet_light),
                        stringResource(id = R.string.settings_theme_mode_monet_dark),
                    )
                    var themeMode by rememberSaveable {
                        mutableIntStateOf(prefs.getInt("color_mode", 0))
                    }
                    SuperDropdown(
                        title = stringResource(id = R.string.settings_theme),
                        summary = stringResource(id = R.string.settings_theme_summary),
                        items = themeItems,
                        startAction = {
                            Icon(
                                Icons.Rounded.Palette,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_theme),
                                tint = RazerColors.GreenDim
                            )
                        },
                        selectedIndex = themeMode,
                        onSelectedIndexChange = { index ->
                            prefs.edit { putInt("color_mode", index) }
                            themeMode = index
                        }
                    )

                    // ── Language setting ──
                    val languageItems = listOf(
                        stringResource(id = R.string.settings_theme_mode_system),
                        stringResource(id = R.string.settings_language_zh),
                        stringResource(id = R.string.settings_language_en),
                    )
                    var languageMode by rememberSaveable {
                        mutableIntStateOf(prefs.getInt("language_mode", 0))
                    }
                    SuperDropdown(
                        title = stringResource(id = R.string.settings_language),
                        summary = stringResource(id = R.string.settings_language_summary),
                        items = languageItems,
                        startAction = {
                            Icon(
                                Icons.Rounded.Language,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_language),
                                tint = RazerColors.GreenDim
                            )
                        },
                        selectedIndex = languageMode,
                        onSelectedIndexChange = { index ->
                            prefs.edit { putInt("language_mode", index) }
                            languageMode = index
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                val localeManager = context.getSystemService(LocaleManager::class.java)
                                val tag = when (index) {
                                    1 -> "zh-CN"
                                    2 -> "en"
                                    else -> "" // empty = follow system
                                }
                                localeManager.applicationLocales = LocaleList.forLanguageTags(tag)
                            } else {
                                activity?.recreate()
                            }
                        }
                    )

                    // ── Key Color (always visible, enabled only for Monet) ──
                    val isMonetTheme = themeMode in 3..5
                    val keyColorSummary = if (isMonetTheme) {
                        stringResource(id = R.string.settings_key_color_summary)
                    } else {
                        stringResource(id = R.string.settings_key_color_monet_hint)
                    }
                    run {
                        val colorItems = listOf(
                            stringResource(id = R.string.settings_key_color_default),
                            stringResource(id = R.string.color_red),
                            stringResource(id = R.string.color_pink),
                            stringResource(id = R.string.color_purple),
                            stringResource(id = R.string.color_deep_purple),
                            stringResource(id = R.string.color_indigo),
                            stringResource(id = R.string.color_blue),
                            stringResource(id = R.string.color_cyan),
                            stringResource(id = R.string.color_teal),
                            stringResource(id = R.string.color_green),
                            stringResource(id = R.string.color_yellow),
                            stringResource(id = R.string.color_amber),
                            stringResource(id = R.string.color_orange),
                            stringResource(id = R.string.color_brown),
                            stringResource(id = R.string.color_blue_grey),
                            stringResource(id = R.string.color_sakura),
                        )
                        val colorValues = listOf(
                            0,
                            Color(0xFFF44336).toArgb(),
                            Color(0xFFE91E63).toArgb(),
                            Color(0xFF9C27B0).toArgb(),
                            Color(0xFF673AB7).toArgb(),
                            Color(0xFF3F51B5).toArgb(),
                            Color(0xFF2196F3).toArgb(),
                            Color(0xFF00BCD4).toArgb(),
                            Color(0xFF009688).toArgb(),
                            Color(0xFF4FAF50).toArgb(),
                            Color(0xFFFFEB3B).toArgb(),
                            Color(0xFFFFC107).toArgb(),
                            Color(0xFFFF9800).toArgb(),
                            Color(0xFF795548).toArgb(),
                            Color(0xFF607D8F).toArgb(),
                            Color(0xFFFF9CA8).toArgb(),
                        )
                        var keyColorIndex by rememberSaveable {
                            mutableIntStateOf(
                                colorValues.indexOf(prefs.getInt("key_color", 0)).takeIf { it >= 0 } ?: 0
                            )
                        }
                        SuperDropdown(
                            title = stringResource(id = R.string.settings_key_color),
                            summary = keyColorSummary,
                            items = colorItems,
                            startAction = {
                                Icon(
                                    Icons.Rounded.Colorize,
                                    modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                    contentDescription = stringResource(id = R.string.settings_key_color),
                                    tint = if (isMonetTheme) RazerColors.GreenDim else RazerColors.T40
                                )
                            },
                            enabled = isMonetTheme,
                            selectedIndex = keyColorIndex,
                            onSelectedIndexChange = { index ->
                                prefs.edit { putInt("key_color", colorValues[index]) }
                                keyColorIndex = index
                            }
                        )
                    }

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        var enablePredictiveBack by rememberSaveable {
                            mutableStateOf(prefs.getBoolean("enable_predictive_back", false))
                        }
                        SuperSwitch(
                            title = stringResource(id = R.string.settings_enable_predictive_back),
                            summary = stringResource(id = R.string.settings_enable_predictive_back_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.Adb,
                                    modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                    contentDescription = stringResource(id = R.string.settings_enable_predictive_back),
                                    tint = RazerColors.GreenDim
                                )
                            },
                            checked = enablePredictiveBack,
                            onCheckedChange = {
                                prefs.edit { putBoolean("enable_predictive_back", it) }
                                enablePredictiveBack = it
                                KernelSUApplication.setEnableOnBackInvokedCallback(context.applicationInfo, it)
                                activity?.recreate()
                            }
                        )
                    }
                    var pageScale by rememberSaveable {
                        mutableFloatStateOf(prefs.getFloat("page_scale", 1.0f))
                    }
                    SuperArrow(
                        title = stringResource(id = R.string.settings_page_scale),
                        summary = stringResource(id = R.string.settings_page_scale_summary),
                        startAction = {
                            Icon(
                                Icons.Rounded.AspectRatio,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_page_scale),
                                tint = RazerColors.GreenDim
                            )
                        },
                        endActions = {
                            Text(
                                text = "${(pageScale * 100).toInt()}%",
                                color = colorScheme.onSurfaceVariantActions,
                            )
                        },
                        onClick = { showScaleDialog.value = !showScaleDialog.value },
                        holdDownState = showScaleDialog.value,
                        bottomAction = {
                            Slider(
                                value = pageScale,
                                onValueChange = {
                                    pageScale = it
                                },
                                onValueChangeFinished = {
                                    prefs.edit { putFloat("page_scale", pageScale) }
                                },
                                valueRange = 0.75f..1.1f,
                                showKeyPoints = true,
                                keyPoints = listOf(0.75f, 0.85f, 1f, 1.1f),
                                magnetThreshold = 0.01f,
                                hapticEffect = SliderDefaults.SliderHapticEffect.Step,
                            )
                        },
                    )
                    ScaleDialog(
                        showScaleDialog,
                        volumeState = { pageScale },
                        onVolumeChange = {
                            pageScale = it
                            prefs.edit { putFloat("page_scale", it) }
                        }
                    )
                }

                // ══ 内核特性 ══
                Text(
                    text = stringResource(id = R.string.settings_section_kernel_features),
                    modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 4.dp),
                    color = RazerColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier
                        .fillMaxWidth(),
                ) {
                    val suCompatModeItems = listOf(
                        stringResource(id = R.string.settings_mode_enable_by_default),
                        stringResource(id = R.string.settings_mode_disable_until_reboot),
                        stringResource(id = R.string.settings_mode_disable_always),
                    )

                    val currentSuEnabled = if (isKsuValid) Natives.isSuEnabled() else false
                    var suCompatMode by rememberSaveable { mutableIntStateOf(if (!currentSuEnabled) 1 else 0) }
                    val suPersistValue by produceState(initialValue = null as Long?) {
                        value = if (isKsuValid) getFeaturePersistValue("su_compat") else null
                    }
                    LaunchedEffect(suPersistValue) {
                        suPersistValue?.let { v ->
                            suCompatMode = if (v == 0L) 2 else if (!currentSuEnabled) 1 else 0
                        }
                    }
                    val suStatus by produceState(initialValue = "") {
                        value = if (isKsuValid) getFeatureStatus("su_compat") else ""
                    }
                    val suSummary = when {
                        !isKsuValid -> stringResource(id = R.string.settings_not_installed_summary)
                        suStatus == "unsupported" -> stringResource(id = R.string.feature_status_unsupported_summary)
                        suStatus == "managed" -> stringResource(id = R.string.feature_status_managed_summary)
                        else -> stringResource(id = R.string.settings_sucompat_summary)
                    }
                    SuperDropdown(
                        title = stringResource(id = R.string.settings_sucompat),
                        summary = suSummary,
                        items = suCompatModeItems,
                        startAction = {
                            Icon(
                                Icons.Rounded.RemoveModerator,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_sucompat),
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid && suStatus == "supported",
                        selectedIndex = suCompatMode,
                        onSelectedIndexChange = { index ->
                            when (index) {
                                0 -> if (Natives.setSuEnabled(true)) {
                                    execKsud("feature save", true)
                                    prefs.edit { putInt("su_compat_mode", 0) }
                                    suCompatMode = 0
                                }
                                1 -> if (Natives.setSuEnabled(true)) {
                                    execKsud("feature save", true)
                                    if (Natives.setSuEnabled(false)) {
                                        prefs.edit { putInt("su_compat_mode", 0) }
                                        suCompatMode = 1
                                    }
                                }
                                2 -> if (Natives.setSuEnabled(false)) {
                                    execKsud("feature save", true)
                                    prefs.edit { putInt("su_compat_mode", 2) }
                                    suCompatMode = 2
                                }
                            }
                        }
                    )

                    var isKernelUmountEnabled by rememberSaveable { mutableStateOf(if (isKsuValid) Natives.isKernelUmountEnabled() else false) }
                    val umountStatus by produceState(initialValue = "") {
                        value = if (isKsuValid) getFeatureStatus("kernel_umount") else ""
                    }
                    val umountSummary = when {
                        !isKsuValid -> stringResource(id = R.string.settings_not_installed_summary)
                        umountStatus == "unsupported" -> stringResource(id = R.string.feature_status_unsupported_summary)
                        umountStatus == "managed" -> stringResource(id = R.string.feature_status_managed_summary)
                        else -> stringResource(id = R.string.settings_kernel_umount_summary)
                    }
                    SuperSwitch(
                        title = stringResource(id = R.string.settings_kernel_umount),
                        summary = umountSummary,
                        startAction = {
                            Icon(
                                Icons.Rounded.RemoveCircle,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_kernel_umount),
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid && umountStatus == "supported",
                        checked = isKernelUmountEnabled,
                        onCheckedChange = { checked ->
                            if (Natives.setKernelUmountEnabled(checked)) {
                                execKsud("feature save", true)
                                isKernelUmountEnabled = checked
                            }
                        }
                    )

                    var umountChecked by rememberSaveable { mutableStateOf(if (isKsuValid) Natives.isDefaultUmountModules() else false) }
                    SuperSwitch(
                        title = stringResource(id = R.string.settings_umount_modules_default),
                        summary = if (isKsuValid) stringResource(id = R.string.settings_umount_modules_default_summary)
                                  else stringResource(id = R.string.settings_not_installed_summary),
                        startAction = {
                            Icon(
                                Icons.Rounded.FolderDelete,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_umount_modules_default),
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid,
                        checked = umountChecked,
                        onCheckedChange = {
                            if (Natives.setDefaultUmountModules(it)) {
                                umountChecked = it
                            }
                        }
                    )

                    // ── Safe Mode info ──
                    val isSafeMode = if (isKsuValid) Natives.isSafeMode else false
                    val safeModeSummary = when {
                        !isKsuValid -> stringResource(id = R.string.settings_not_installed_summary)
                        isSafeMode -> stringResource(id = R.string.settings_safe_mode_summary_on)
                        else -> stringResource(id = R.string.settings_safe_mode_summary_off)
                    }
                    SuperArrow(
                        title = stringResource(id = R.string.safe_mode),
                        summary = safeModeSummary,
                        startAction = {
                            Icon(
                                Icons.Rounded.Security,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.safe_mode),
                                tint = if (isKsuValid && isSafeMode) RazerColors.Danger
                                       else if (isKsuValid) RazerColors.GreenDim
                                       else RazerColors.T40
                            )
                        },
                        enabled = false,
                        onClick = { }
                    )
                }

                // ══ 高级 ══
                Text(
                    text = stringResource(id = R.string.settings_section_advanced),
                    modifier = Modifier.padding(start = 4.dp, top = 16.dp, bottom = 4.dp),
                    color = RazerColors.GreenDim,
                    fontSize = 12.sp,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    letterSpacing = 1.5.sp
                )
                Card(
                    modifier = Modifier
                        .fillMaxWidth(),
                ) {
                    val profileTemplate = stringResource(id = R.string.settings_profile_template)
                    SuperArrow(
                        title = profileTemplate,
                        summary = if (isKsuValid) stringResource(id = R.string.settings_profile_template_summary)
                                  else stringResource(id = R.string.settings_not_installed_summary),
                        startAction = {
                            Icon(
                                Icons.Rounded.Fence,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = profileTemplate,
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid,
                        onClick = {
                            navigator.push(Route.AppProfileTemplate)
                        }
                    )

                    SuperArrow(
                        title = stringResource(id = R.string.send_log),
                        startAction = {
                            Icon(
                                Icons.Rounded.BugReport,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.send_log),
                                tint = RazerColors.GreenDim
                            )
                        },
                        onClick = {
                            showSendLogDialog.value = true
                        },
                    )
                    SendLogDialog(showSendLogDialog, loadingDialog)

                    var enableWebDebugging by rememberSaveable {
                        mutableStateOf(prefs.getBoolean("enable_web_debugging", false))
                    }
                    SuperSwitch(
                        title = stringResource(id = R.string.enable_web_debugging),
                        summary = if (isKsuValid) stringResource(id = R.string.enable_web_debugging_summary)
                                  else stringResource(id = R.string.settings_not_installed_summary),
                        startAction = {
                            Icon(
                                Icons.Rounded.DeveloperMode,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.enable_web_debugging),
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid,
                        checked = enableWebDebugging,
                        onCheckedChange = {
                            prefs.edit { putBoolean("enable_web_debugging", it) }
                            enableWebDebugging = it
                        }
                    )

                    // ── Module Repo entry ──
                    SuperArrow(
                        title = stringResource(id = R.string.settings_module_repo),
                        summary = if (isKsuValid) stringResource(id = R.string.settings_module_repo_summary)
                                  else stringResource(id = R.string.settings_not_installed_summary),
                        startAction = {
                            Icon(
                                Icons.Rounded.Extension,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_module_repo),
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid,
                        onClick = {
                            navigator.push(Route.ModuleRepo)
                        }
                    )

                    // ── Reboot device ──
                    val rebootItems = mutableListOf(
                        stringResource(id = R.string.reboot),
                        stringResource(id = R.string.reboot_recovery),
                        stringResource(id = R.string.reboot_bootloader),
                        stringResource(id = R.string.reboot_download),
                        stringResource(id = R.string.reboot_edl),
                    )
                    val rebootReasons = mutableListOf("", "recovery", "bootloader", "download", "edl")
                    val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager?
                    @Suppress("DEPRECATION")
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && pm?.isRebootingUserspaceSupported == true) {
                        rebootItems.add(1, stringResource(id = R.string.reboot_userspace))
                        rebootReasons.add(1, "userspace")
                    }
                    var rebootSelected by rememberSaveable { mutableIntStateOf(0) }
                    SuperDropdown(
                        title = stringResource(id = R.string.settings_reboot_device),
                        summary = stringResource(id = R.string.settings_reboot_summary),
                        items = rebootItems,
                        startAction = {
                            Icon(
                                Icons.Rounded.PowerSettingsNew,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = stringResource(id = R.string.settings_reboot_device),
                                tint = if (isKsuValid) RazerColors.GreenDim else RazerColors.T40
                            )
                        },
                        enabled = isKsuValid,
                        selectedIndex = rebootSelected,
                        onSelectedIndexChange = { index ->
                            rebootSelected = index
                            reboot(rebootReasons[index])
                        }
                    )

                    // ── Uninstall (always visible) ──
                    val lkmMode = if (isKsuValid) Natives.isLkmMode else false
                    val uninstall = stringResource(id = R.string.settings_uninstall)
                    val uninstallSummary = when {
                        !isKsuValid -> stringResource(id = R.string.settings_not_installed_summary)
                        !lkmMode -> stringResource(id = R.string.settings_uninstall_not_lkm_summary)
                        else -> stringResource(id = R.string.settings_uninstall_summary)
                    }
                    SuperArrow(
                        title = uninstall,
                        summary = uninstallSummary,
                        startAction = {
                            Icon(
                                Icons.Rounded.Delete,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = uninstall,
                                tint = if (isKsuValid && lkmMode) RazerColors.Danger else RazerColors.T40,
                            )
                        },
                        enabled = isKsuValid && lkmMode,
                        onClick = {
                            showUninstallDialog.value = true
                        }
                    )
                    UninstallDialog(showUninstallDialog, navigator)
                }

                Card(
                    modifier = Modifier
                        .padding(vertical = 12.dp)
                        .fillMaxWidth(),
                ) {
                    val about = stringResource(id = R.string.about)
                    SuperArrow(
                        title = about,
                        startAction = {
                            Icon(
                                Icons.Rounded.ContactPage,
                                modifier = Modifier.padding(end = 16.dp).size(20.dp),
                                contentDescription = about,
                                tint = RazerColors.GreenDim
                            )
                        },
                        onClick = {
                            navigator.push(Route.About)
                        }
                    )
                }
                Spacer(Modifier.height(bottomInnerPadding))
            }
        }
    }
}

enum class UninstallType(val icon: ImageVector, val title: Int, val message: Int) {
    TEMPORARY(
        Icons.Rounded.RemoveModerator,
        R.string.settings_uninstall_temporary,
        R.string.settings_uninstall_temporary_message
    ),
    PERMANENT(
        Icons.Rounded.DeleteForever,
        R.string.settings_uninstall_permanent,
        R.string.settings_uninstall_permanent_message
    ),
    RESTORE_STOCK_IMAGE(
        Icons.Rounded.RestartAlt,
        R.string.settings_restore_stock_image,
        R.string.settings_restore_stock_image_message
    ),
    NONE(Icons.Rounded.Adb, 0, 0)
}
