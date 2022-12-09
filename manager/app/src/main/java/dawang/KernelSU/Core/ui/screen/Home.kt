package dawang.KernelSU.Core.ui.screen

import android.content.Context
import android.os.Build
import android.system.Os
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.pm.PackageInfoCompat
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeStyle
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import dawang.KernelSU.Core.KernelVersion
import dawang.KernelSU.Core.Natives
import dawang.KernelSU.Core.R
import dawang.KernelSU.Core.getKernelVersion
import dawang.KernelSU.Core.ui.LocalMainPagerState
import dawang.KernelSU.Core.ui.component.DropdownItem
import dawang.KernelSU.Core.ui.component.RebootListPopup
import dawang.KernelSU.Core.ui.component.rememberConfirmDialog
import dawang.KernelSU.Core.ui.navigation3.Navigator
import dawang.KernelSU.Core.ui.navigation3.Route
import dawang.KernelSU.Core.ui.theme.RazerColors
import dawang.KernelSU.Core.ui.theme.isInDarkTheme
import dawang.KernelSU.Core.ui.util.checkNewVersion
import dawang.KernelSU.Core.ui.util.getModuleCount
import dawang.KernelSU.Core.ui.util.getSELinuxStatus
import dawang.KernelSU.Core.ui.util.getSuperuserCount
import dawang.KernelSU.Core.ui.util.module.LatestVersionInfo
import dawang.KernelSU.Core.ui.util.reboot
import dawang.KernelSU.Core.ui.util.rootAvailable
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.BasicComponentDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Link
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.isDynamicColor
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.window.Dialog

@Composable
fun HomePager(
    navigator: Navigator,
    bottomInnerPadding: Dp
) {
    val kernelVersion = getKernelVersion()
    val scrollBehavior = MiuixScrollBehavior()
    val hazeState = remember { HazeState() }

    val context = LocalContext.current
    val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val checkUpdate = prefs.getBoolean("check_update", true)
    val themeMode = prefs.getInt("color_mode", 0)
    val isDark = isInDarkTheme(themeMode)
    val pageBg = if (isDark) colorScheme.surface else RazerColors.PinkBg

    val hazeStyle = HazeStyle(
        backgroundColor = pageBg,
        tint = HazeTint(pageBg.copy(0.8f))
    )

    var showAboutDialog by remember { mutableStateOf(false) }
    if (showAboutDialog) {
        AboutDialog(isDark = isDark, onDismiss = { showAboutDialog = false })
    }

    Scaffold(
        topBar = {
            TopBar(
                scrollBehavior = scrollBehavior,
                hazeState = hazeState,
                hazeStyle = hazeStyle,
                onAboutClick = { showAboutDialog = true },
            )
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .background(pageBg)
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 16.dp)
                .hazeSource(state = hazeState),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                val isManager = Natives.isManager
                val ksuVersion = if (isManager) Natives.version else null
                val lkmMode = ksuVersion?.let {
                    if (kernelVersion.isGKI()) Natives.isLkmMode else null
                }
                val mainState = LocalMainPagerState.current

                Column(
                    modifier = Modifier.padding(vertical = 12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (ksuVersion != null && !Natives.isLkmMode) {
                        WarningCard(
                            stringResource(id = R.string.home_gki_warning),
                            themeMode
                        )
                    }
                    if (isManager && Natives.requireNewKernel()) {
                        WarningCard(
                            stringResource(id = R.string.require_kernel_version)
                                .format(ksuVersion, Natives.MINIMAL_SUPPORTED_KERNEL),
                            themeMode
                        )
                    }
                    if (ksuVersion != null && !rootAvailable()) {
                        WarningCard(
                            stringResource(id = R.string.grant_root_failed),
                            themeMode
                        )
                    }
                    StatusCard(
                        kernelVersion, ksuVersion, lkmMode,
                        onClickInstall = {
                            navigator.push(Route.Install)
                        },
                        onClickSuperuser = {
                            mainState.animateToPage(1)
                        },
                    onclickModule = {
                            mainState.animateToPage(3)
                        },
                        themeMode = themeMode
                    )

                    if (checkUpdate) {
                        UpdateCard(themeMode)
                    }
                    InfoCard(isDark)
                    LkmGuideCard(isDark)
                    DonateCard(isDark)
                    LearnMoreCard(isDark)
                    CeManagerCard(isDark)
                }
                Spacer(Modifier.height(bottomInnerPadding))
            }
        }
    }
}

@Composable
fun UpdateCard(
    themeMode: Int,
) {
    val context = LocalContext.current
    val latestVersionInfo = LatestVersionInfo()
    val newVersion by produceState(initialValue = latestVersionInfo) {
        value = withContext(Dispatchers.IO) {
            checkNewVersion()
        }
    }

    val currentVersionCode = getManagerVersion(context).second
    val newVersionCode = newVersion.versionCode
    val newVersionUrl = newVersion.downloadUrl
    val changelog = newVersion.changelog

    val uriHandler = LocalUriHandler.current
    val title = stringResource(id = R.string.module_changelog)
    val updateText = stringResource(id = R.string.module_update)

    AnimatedVisibility(
        visible = newVersionCode > currentVersionCode,
        enter = fadeIn() + expandVertically(),
        exit = shrinkVertically() + fadeOut()
    ) {
        val updateDialog = rememberConfirmDialog(onConfirm = { uriHandler.openUri(newVersionUrl) })
        WarningCard(
            message = stringResource(id = R.string.new_version_available).format(newVersionCode),
            themeMode, colorScheme.outline
        ) {
            if (changelog.isEmpty()) {
                uriHandler.openUri(newVersionUrl)
            } else {
                updateDialog.showConfirm(
                    title = title,
                    content = changelog,
                    markdown = true,
                    confirm = updateText
                )
            }
        }
    }
}

@Composable
fun RebootDropdownItem(
    @StringRes id: Int, reason: String = "",
    showTopPopup: MutableState<Boolean>,
    optionSize: Int,
    index: Int,
) {
    DropdownItem(
        text = stringResource(id),
        optionSize = optionSize,
        onSelectedIndexChange = {
            reboot(reason)
            showTopPopup.value = false
        },
        index = index
    )
}

@Composable
private fun TopBar(
    scrollBehavior: ScrollBehavior,
    hazeState: HazeState,
    hazeStyle: HazeStyle,
    onAboutClick: () -> Unit = {},
) {
    TopAppBar(
        modifier = Modifier.hazeEffect(hazeState) {
            style = hazeStyle
            blurRadius = 30.dp
            noiseFactor = 0f
        },
        color = Color.Transparent,
        title = stringResource(R.string.app_name),
        actions = {
            GlowingAboutButton(onClick = onAboutClick)
            RebootListPopup(
                modifier = Modifier.padding(end = 16.dp),
            )
        },
        scrollBehavior = scrollBehavior
    )
}

@Composable
private fun StatusCard(
    kernelVersion: KernelVersion,
    ksuVersion: Int?,
    lkmMode: Boolean?,
    onClickInstall: () -> Unit = {},
    onClickSuperuser: () -> Unit = {},
    onclickModule: () -> Unit = {},
    themeMode: Int,
) {
    val isDark = isInDarkTheme(themeMode)
    Column(
        modifier = Modifier
    ) {
        when {
            ksuVersion != null -> {
                val safeModeText = if (Natives.isSafeMode) {
                    stringResource(id = R.string.safe_mode_on)
                } else {
                    stringResource(id = R.string.safe_mode_off)
                }

                val workingMode = when (lkmMode) {
                    null -> ""
                    true -> " <LKM>"
                    else -> " <GKI>"
                }

                val workingText = stringResource(id = R.string.home_working) + workingMode
                val gkiText = if (lkmMode == true) "LKM" else "GKI 2.0"

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(170.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    // 左侧主状态卡片 - 绿色渐变边框
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .clip(RoundedCornerShape(16.dp))
                            .background(
                                brush = androidx.compose.ui.graphics.Brush.linearGradient(
                                    colors = listOf(
                                        RazerColors.Green.copy(alpha = 0.10f),
                                        RazerColors.Green.copy(alpha = 0.02f)
                                    )
                                )
                            )
                            .border(
                                width = 1.dp,
                                color = RazerColors.GreenBorder,
                                shape = RoundedCornerShape(16.dp)
                            )
                    ) {
                        // 背景大图标
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .offset(40.dp, 30.dp),
                            contentAlignment = Alignment.BottomEnd
                        ) {
                            Icon(
                                modifier = Modifier.size(120.dp),
                                imageVector = Icons.Rounded.CheckCircleOutline,
                                tint = RazerColors.Green.copy(alpha = 0.08f),
                                contentDescription = null
                            )
                        }
                        // 内容
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(20.dp)
                        ) {
                            // 运行中徽章
                            Row(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(RazerColors.Green.copy(alpha = 0.12f))
                                    .border(
                                        width = 1.dp,
                                        color = RazerColors.Green.copy(alpha = 0.3f),
                                        shape = RoundedCornerShape(8.dp)
                                    )
                                    .padding(horizontal = 10.dp, vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                // 脉冲小圆点
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(RazerColors.Green)
                                )
                                Text(
                                    text = stringResource(R.string.home_running),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = RazerColors.Green
                                )
                            }
                            Spacer(Modifier.height(12.dp))
                            // 工作正常 <LKM>
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = stringResource(id = R.string.home_working),
                                    fontSize = 22.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = colorScheme.onSurface
                                )
                                Text(
                                    text = workingMode,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Normal,
                                    color = RazerColors.Green
                                )
                            }
                            Spacer(Modifier.height(2.dp))
                            // 版本号
                            Text(
                                text = stringResource(R.string.home_working_version, ksuVersion),
                                fontSize = 13.sp,
                                color = colorScheme.onSurfaceVariantSummary
                            )
                            // GKI 2.0 · 安全模式关闭
                            Text(
                                text = "$gkiText · $safeModeText",
                                fontSize = 13.sp,
                                color = colorScheme.outline
                            )
                        }
                    }
                    // 右侧统计卡片
                    Column(
                        modifier = Modifier
                            .width(130.dp)
                            .fillMaxHeight(),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // 超级用户卡片
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            colors = CardDefaults.defaultColors(color = if (isDark) colorScheme.primaryContainer else RazerColors.PinkElevated),
                            insideMargin = PaddingValues(16.dp),
                            onClick = { onClickSuperuser() },
                            showIndication = true,
                            pressFeedbackType = PressFeedbackType.Tilt
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                verticalArrangement = Arrangement.Center
                            ) {
                                Text(
                                    text = stringResource(R.string.superuser),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = colorScheme.onSurfaceVariantSummary
                                )
                                Text(
                                    text = getSuperuserCount().toString(),
                                    fontSize = 30.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = RazerColors.Green,
                                    letterSpacing = (-1).sp
                                )
                            }
                        }
                        // 模块卡片
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            colors = CardDefaults.defaultColors(color = if (isDark) colorScheme.primaryContainer else RazerColors.PinkElevated),
                            insideMargin = PaddingValues(16.dp),
                            onClick = { onclickModule() },
                            showIndication = true,
                            pressFeedbackType = PressFeedbackType.Tilt
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                verticalArrangement = Arrangement.Center
                            ) {
                                Text(
                                    text = stringResource(R.string.module),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = colorScheme.onSurfaceVariantSummary
                                )
                                Text(
                                    text = getModuleCount().toString(),
                                    fontSize = 30.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = RazerColors.Green,
                                    letterSpacing = (-1).sp
                                )
                            }
                        }
                    }
                }
            }

            kernelVersion.isGKI() -> {
                // 未安装状态 - 点击跳转到安装页面
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.defaultColors(color = if (isDark) colorScheme.primaryContainer else RazerColors.PinkCard),
                    onClick = { onClickInstall() },
                    showIndication = true,
                    pressFeedbackType = PressFeedbackType.Tilt
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            Icons.Rounded.ErrorOutline,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp),
                            tint = colorScheme.onSurfaceVariantSummary
                        )
                        Column {
                            Text(
                                text = stringResource(R.string.home_not_installed),
                                fontSize = 16.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = colorScheme.onSurface
                            )
                            Text(
                                text = stringResource(R.string.home_click_to_install),
                                fontSize = 13.sp,
                                color = colorScheme.outline
                            )
                        }
                    }
                }
            }

            else -> {
                // 不支持状态
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(16.dp))
                        .background(
                            brush = androidx.compose.ui.graphics.Brush.linearGradient(
                                colors = if (isDark) listOf(
                                    colorScheme.primary.copy(alpha = 0.10f),
                                    colorScheme.primary.copy(alpha = 0.03f)
                                ) else listOf(
                                    RazerColors.PinkCard,
                                    RazerColors.PinkCard
                                )
                            )
                        )
                        .border(
                            width = 1.dp,
                            color = if (isDark) colorScheme.primary.copy(alpha = 0.15f) else RazerColors.PinkBorder,
                            shape = RoundedCornerShape(16.dp)
                        )
                        .padding(16.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            Icons.Rounded.ErrorOutline,
                            contentDescription = null,
                            modifier = Modifier.size(24.dp),
                            tint = RazerColors.Danger
                        )
                        Column {
                            Text(
                                text = stringResource(R.string.home_unsupported),
                                fontSize = 16.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = colorScheme.onSurface
                            )
                            Text(
                                text = stringResource(R.string.home_unsupported_reason),
                                fontSize = 13.sp,
                                color = colorScheme.outline
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun WarningCard(
    message: String,
    themeMode: Int,
    color: Color? = null,
    onClick: (() -> Unit)? = null,
) {
    // 使用 Razer 风格的警告卡片
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(RazerColors.DangerBg)
            .border(
                width = 1.dp,
                color = RazerColors.DangerBorder,
                shape = RoundedCornerShape(16.dp)
            )
            .then(
                if (onClick != null) {
                    Modifier.padding(0.dp) // 可点击时使用默认 padding
                } else {
                    Modifier.padding(0.dp)
                }
            )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                imageVector = Icons.Rounded.ErrorOutline,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
                tint = RazerColors.Danger
            )
            Text(
                text = message,
                color = Color(0xFFFF6B6B),
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                lineHeight = 18.sp
            )
        }
    }
}

@Composable
fun LearnMoreCard(isDark: Boolean = true) {
    val uriHandler = LocalUriHandler.current
    val url = stringResource(R.string.home_learn_kernelsu_url)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(color = if (isDark) colorScheme.primaryContainer else RazerColors.PinkCard),
        onClick = { uriHandler.openUri(url) },
        showIndication = true,
        pressFeedbackType = PressFeedbackType.Tilt
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.home_learn_kernelsu),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = RazerColors.Green
                )
                Text(
                    text = stringResource(R.string.home_click_to_learn_kernelsu),
                    fontSize = 12.sp,
                    color = colorScheme.outline,
                    lineHeight = 16.sp
                )
            }
            Icon(
                imageVector = MiuixIcons.Link,
                tint = RazerColors.Green,
                contentDescription = null
            )
        }
    }
}

@Composable
fun LkmGuideCard(isDark: Boolean = true) {
    val uriHandler = LocalUriHandler.current
    val url = stringResource(R.string.home_lkm_guide_url)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(
                brush = androidx.compose.ui.graphics.Brush.linearGradient(
                    colors = if (isDark) listOf(
                        colorScheme.primary.copy(alpha = 0.12f),
                        colorScheme.primary.copy(alpha = 0.03f)
                    ) else listOf(
                        RazerColors.PinkCard,
                        RazerColors.PinkCard
                    )
                )
            )
            .border(
                width = 1.dp,
                color = if (isDark) colorScheme.primary.copy(alpha = 0.15f) else RazerColors.PinkBorder,
                shape = RoundedCornerShape(16.dp)
            )
    ) {
        // Green accent line
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(2.dp)
                .background(RazerColors.Green)
        )
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = stringResource(R.string.home_lkm_guide_title),
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
                color = RazerColors.Green
            )
            Text(
                text = stringResource(R.string.home_lkm_guide_desc),
                fontSize = 12.sp,
                color = colorScheme.outline,
                lineHeight = 16.sp
            )
            // Steps
            Column(
                modifier = Modifier.padding(top = 4.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Text(
                    text = stringResource(R.string.home_lkm_guide_step1),
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                    lineHeight = 16.sp
                )
                Text(
                    text = stringResource(R.string.home_lkm_guide_step2),
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                    lineHeight = 16.sp
                )
                Text(
                    text = stringResource(R.string.home_lkm_guide_step3),
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                    lineHeight = 16.sp
                )
                Text(
                    text = stringResource(R.string.home_lkm_guide_step4),
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                    lineHeight = 16.sp
                )
            }
            // Download button row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(RazerColors.Green.copy(alpha = 0.10f))
                    .clickable { uriHandler.openUri(url) }
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.home_lkm_guide_action),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = RazerColors.Green
                )
                Icon(
                    imageVector = MiuixIcons.Link,
                    tint = RazerColors.Green,
                    contentDescription = null
                )
            }
        }
    }
}

@Composable
fun DonateCard(isDark: Boolean = true) {
    val uriHandler = LocalUriHandler.current
    val qqGroupUrl = "https://qm.qq.com/q/BRHFfZrjri"

    // 使用 card-accent 样式 - 绿色顶部边框
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(
                brush = androidx.compose.ui.graphics.Brush.linearGradient(
                    colors = if (isDark) listOf(
                        colorScheme.primary.copy(alpha = 0.12f),
                        colorScheme.primary.copy(alpha = 0.03f)
                    ) else listOf(
                        RazerColors.PinkCard,
                        RazerColors.PinkCard
                    )
                )
            )
            .border(
                width = 1.dp,
                color = if (isDark) colorScheme.primary.copy(alpha = 0.15f) else RazerColors.PinkBorder,
                shape = RoundedCornerShape(16.dp)
            )
            .clickable { uriHandler.openUri(qqGroupUrl) }
    ) {
        // 绿色顶部强调线
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(2.dp)
                .background(RazerColors.Green)
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.home_support_title),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = RazerColors.Green
                )
                Text(
                    text = "QQ群: 325900535 · 点击加入",
                    fontSize = 12.sp,
                    color = colorScheme.outline,
                    lineHeight = 16.sp
                )
            }
            Icon(
                imageVector = MiuixIcons.Link,
                tint = RazerColors.Green,
                contentDescription = null
            )
        }
    }
}

@Composable
private fun InfoCard(isDark: Boolean = true) {
    val context = LocalContext.current
    val uname = Os.uname()
    val managerVersion = getManagerVersion(context)
    val selinuxStatus = getSELinuxStatus()

    // 使用 Razer 风格的信息卡片 - 绿色顶部边框 (card-accent)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(
                brush = androidx.compose.ui.graphics.Brush.linearGradient(
                    colors = if (isDark) listOf(
                        colorScheme.primary.copy(alpha = 0.12f),
                        colorScheme.primary.copy(alpha = 0.03f)
                    ) else listOf(
                        RazerColors.PinkCard,
                        RazerColors.PinkCard
                    )
                )
            )
            .border(
                width = 1.dp,
                color = if (isDark) colorScheme.primary.copy(alpha = 0.15f) else RazerColors.PinkBorder,
                shape = RoundedCornerShape(16.dp)
            )
    ) {
        // 绿色顶部强调线
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(2.dp)
                .background(RazerColors.Green)
        )
        // 信息行
        InfoRow(
            label = stringResource(R.string.home_kernel),
            value = uname.release,
            showDivider = true,
            isDark = isDark
        )
        InfoRow(
            label = stringResource(R.string.home_manager_version),
            value = "${managerVersion.first} (${managerVersion.second})",
            showDivider = true,
            isDark = isDark
        )
        InfoRow(
            label = stringResource(R.string.home_fingerprint),
            value = Build.FINGERPRINT,
            showDivider = true,
            isDark = isDark
        )
        InfoRow(
            label = stringResource(R.string.home_selinux_status),
            value = selinuxStatus,
            isAccent = true,
            showDivider = false,
            isDark = isDark
        )
    }
}

@Composable
private fun InfoRow(
    label: String,
    value: String,
    isAccent: Boolean = false,
    showDivider: Boolean = true,
    isDark: Boolean = true
) {
    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 13.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = label,
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium,
                color = RazerColors.Green
            )
            Text(
                text = value,
                fontSize = 13.sp,
                color = if (isAccent) RazerColors.Green else colorScheme.outline,
                fontWeight = if (isAccent) FontWeight.SemiBold else FontWeight.Normal,
                textAlign = TextAlign.End,
                modifier = Modifier.weight(1f, fill = false).padding(start = 16.dp),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (showDivider) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(1.dp)
                    .background(if (isDark) colorScheme.primary.copy(alpha = 0.12f) else RazerColors.PinkBorder)
            )
        }
    }
}

@Composable
fun CeManagerCard(isDark: Boolean = true) {
    val uriHandler = LocalUriHandler.current
    val ceUrl = "https://www.daw111.asia/"

    // CE 卡片使用绿色渐变背景 (ce-card 样式)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(
                brush = androidx.compose.ui.graphics.Brush.linearGradient(
                    colors = if (isDark) listOf(
                        RazerColors.Green.copy(alpha = 0.06f),
                        colorScheme.primaryContainer
                    ) else listOf(
                        RazerColors.Green.copy(alpha = 0.06f),
                        RazerColors.PinkCard
                    )
                )
            )
            .border(
                width = 1.dp,
                color = if (isDark) RazerColors.GreenBorder else RazerColors.PinkBorder,
                shape = RoundedCornerShape(16.dp)
            )
    ) {
        Column {
            // Header
            Row(
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // CE logo
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(RazerColors.Green),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "CE",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Black,
                        color = Color.Black
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.ce_manager_title),
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = RazerColors.Green
                    )
                    Text(
                        text = stringResource(R.string.ce_manager_version),
                        fontSize = 11.sp,
                        color = colorScheme.outline
                    )
                }
                Icon(
                    imageVector = MiuixIcons.Link,
                    tint = RazerColors.GreenDim,
                    contentDescription = null
                )
            }

            // Body
            Column(
                modifier = Modifier.padding(horizontal = 16.dp)
            ) {
                // Description
                Text(
                    text = stringResource(R.string.ce_manager_desc),
                    fontSize = 13.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                    lineHeight = 18.sp
                )
                Spacer(Modifier.height(12.dp))
                // Tags
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    val tags = listOf(
                        R.string.ce_tag_ide,
                        R.string.ce_tag_frida,
                        R.string.ce_tag_apk,
                        R.string.ce_tag_git,
                        R.string.ce_tag_clean
                    )
                    tags.forEach { tagRes ->
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(RazerColors.GreenBg)
                                .border(
                                    width = 1.dp,
                                    color = RazerColors.Green.copy(alpha = 0.12f),
                                    shape = RoundedCornerShape(6.dp)
                                )
                                .padding(horizontal = 8.dp, vertical = 3.dp)
                        ) {
                            Text(
                                text = stringResource(tagRes),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = RazerColors.GreenDim
                            )
                        }
                    }
                }
            }

            // Download button
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(RazerColors.Green)
                    .clickable { uriHandler.openUri(ceUrl) }
                    .padding(vertical = 10.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = MiuixIcons.Link,
                        tint = Color.Black,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = stringResource(R.string.ce_manager_download),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.Black
                    )
                }
            }
        }
    }
}

fun getManagerVersion(context: Context): Pair<String, Long> {
    val packageInfo = runCatching {
        context.packageManager.getPackageInfo(context.packageName, 0)
    }.getOrNull()
    if (packageInfo == null) {
        return Pair("unknown", 0L)
    }
    val versionCode = PackageInfoCompat.getLongVersionCode(packageInfo)
    return Pair(packageInfo.versionName ?: "unknown", versionCode)
}

@Composable
private fun GlowingAboutButton(onClick: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "glow")
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glowAlpha"
    )
    val glowColor = RazerColors.Green

    Box(
        modifier = Modifier
            .padding(end = 4.dp)
            .size(36.dp)
            .drawBehind {
                drawCircle(
                    color = glowColor.copy(alpha = glowAlpha * 0.45f),
                    radius = size.minDimension / 2 + 6.dp.toPx()
                )
                drawCircle(
                    color = glowColor.copy(alpha = glowAlpha * 0.2f),
                    radius = size.minDimension / 2 + 12.dp.toPx()
                )
            }
            .clip(RoundedCornerShape(50))
            .background(glowColor.copy(alpha = 0.15f))
            .border(
                width = 1.dp,
                color = glowColor.copy(alpha = glowAlpha * 0.6f),
                shape = RoundedCornerShape(50)
            )
            .clickable { onClick() },
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "?",
            fontSize = 16.sp,
            fontWeight = FontWeight.Black,
            color = glowColor
        )
    }
}

@Composable
private fun AboutDialog(isDark: Boolean, onDismiss: () -> Unit) {
    val dialogBg = if (isDark) colorScheme.surfaceContainer else RazerColors.PinkCard
    val textSecondary = colorScheme.onSurfaceVariantSummary
    val textDim = colorScheme.outline
    val accent = RazerColors.Green
    val scrollState = rememberScrollState()

    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(20.dp))
                .background(dialogBg)
                .border(
                    width = 1.dp,
                    color = if (isDark) colorScheme.primary.copy(alpha = 0.15f) else RazerColors.PinkBorder,
                    shape = RoundedCornerShape(20.dp)
                )
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(2.dp)
                    .background(accent)
            )
            Column(
                modifier = Modifier
                    .verticalScroll(scrollState)
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text(
                    text = "\u5173\u4e8e KernelSU Core",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = accent
                )

                Text(
                    text = "\u8bf4\u5b9e\u8bdd\uff0c\u8fd9\u4e2a\u9879\u76ee\u7684\u8bde\u751f\u7eaf\u5c5e\u610f\u5916\u3002\n\n" +
                            "\u67d0\u5929\u95f2\u6765\u65e0\u4e8b\u7ffb\u4e86\u7ffb KernelSU \u7684\u6e90\u7801\uff0c\u7ed3\u679c\u4e0d\u770b\u4e0d\u77e5\u9053" +
                            "\u2014\u2014\u597d\u5bb6\u4f19\uff0c\u8fd9\u75d5\u8ff9\u7559\u7684\uff0c\u6bd4\u72af\u7f6a\u73b0\u573a\u8fd8\u5468\u5230\u3002" +
                            "\u5185\u6838\u7b26\u53f7\u8868\u91cc\u5927\u5927\u65b9\u65b9\u5199\u7740\u201c\u6211\u5728\u8fd9\u513f\u201d\uff0c" +
                            "/proc \u5e95\u4e0b\u5404\u79cd\u4fe1\u606f\u8ddf\u5199\u65e5\u8bb0\u4f3c\u7684\uff0c" +
                            "\u6302\u8f7d\u70b9\u66b4\u9732\u5f97\u50cf\u5728\u505a\u81ea\u6211\u4ecb\u7ecd\u3002\n\n" +
                            "\u4f5c\u4e3a\u4e00\u4e2a\u6709\u5f3a\u8feb\u75c7\u7684\u4eba\uff0c\u6211\u5b9e\u5728\u5fcd\u4e0d\u4e86\u3002\n\n" +
                            "\u4e8e\u662f\u82b1\u4e86\u6574\u6574\u4e00\u5929\uff08\u5bf9\uff0c\u5c31\u4e00\u5929\uff0c\u522b\u95ee\u600e\u4e48\u505a\u5230\u7684\uff09\uff0c" +
                            "\u57fa\u4e8e KernelSU \u505a\u4e86\u4ebf\u70b9\u70b9\u6539\u8fdb\uff1a",
                    fontSize = 13.sp,
                    color = textSecondary,
                    lineHeight = 20.sp
                )

                AboutFeatureItem(
                    title = "\u5185\u6838\u7b26\u53f7\u8868\u6e05\u7406 + \u6a21\u5757\u9690\u533f\u52a0\u8f7d",
                    desc = "\u628a\u90a3\u4e9b\u201c\u6b64\u5730\u65e0\u94f6\u4e09\u767e\u4e24\u201d\u7684\u5185\u6838\u6807\u8bb0\u5168\u62b9\u4e86\uff0c\u6a21\u5757\u52a0\u8f7d\u6539\u6210\u9759\u9ed8\u6a21\u5f0f\u2014\u2014\u52a0\u8f7d\u5b8c\u8ddf\u6ca1\u6765\u8fc7\u4e00\u6837\u3002",
                    isDark = isDark
                )
                AboutFeatureItem(
                    title = "/proc \u4fe1\u606f\u5168\u9762\u51c0\u5316",
                    desc = "wchan\u3001stack\u3001maps\u3001cmdline\u3001status\u3001environ\u3001cgroup\u2026\u2026" +
                            "25+ \u79cd /proc \u6761\u76ee\u9010\u4e00\u8fc7\u6ee4\u3002\u68c0\u6d4b\u5de5\u5177\u60f3\u8bfb\u6709\u7528\u4fe1\u606f\uff1f\u505a\u68a6\u3002",
                    isDark = isDark
                )
                AboutFeatureItem(
                    title = "\u7cfb\u7edf\u5c5e\u6027\u6821\u6b63",
                    desc = "\u90a3\u4e9b\u4e00\u773c\u5047\u7684\u5c5e\u6027\u503c\uff0c\u5168\u7ed9\u6539\u56de\u6b63\u5e38\u3002\u5c31\u8fd9\u4e48\u81ea\u4fe1\u3002",
                    isDark = isDark
                )
                AboutFeatureItem(
                    title = "\u6302\u8f7d\u4fe1\u606f + \u5185\u6838\u65e5\u5fd7\u51c0\u5316",
                    desc = "mount \u4fe1\u606f\u548c\u5185\u6838\u65e5\u5fd7\u91cc\u7684\u86db\u4e1d\u9a6c\u8ff9\uff0c\u7edf\u7edf\u5904\u7406\u5e72\u51c0\u3002",
                    isDark = isDark
                )
                AboutFeatureItem(
                    title = "\u8fdb\u7a0b\u7ea7\u9690\u79c1\u4e09\u4ef6\u5957",
                    desc = "\u9690\u853d\u6267\u884c\u3001\u6587\u4ef6 I/O \u75d5\u8ff9\u6e05\u9664\u3001\u8fdb\u7a0b\u95f4\u901a\u4fe1\u4fdd\u62a4\u2014\u2014\u4ece\u8fdb\u7a0b\u7ef4\u5ea6\u505a\u5230\u65e0\u75d5\u3002",
                    isDark = isDark
                )
                AboutFeatureItem(
                    title = "\u542f\u52a8\u75d5\u8ff9\u6e05\u7406",
                    desc = "\u5f00\u673a\u8fc7\u7a0b\u7559\u4e0b\u7684\u201c\u5230\u6b64\u4e00\u6e38\u201d\uff1f\u542f\u52a8\u5b8c\u81ea\u52a8\u64e6\u9664\u3002",
                    isDark = isDark
                )
                AboutFeatureItem(
                    title = "\u8c03\u8bd5\u63a5\u53e3\u7ba1\u63a7",
                    desc = "ptrace \u4e4b\u7c7b\u7684\u8c03\u8bd5\u63a5\u53e3\u5173\u5f97\u6b7b\u6b7b\u7684\u3002\u60f3\u52a8\u6001\u5206\u6790\uff1f\u53e6\u8bf7\u9ad8\u660e\u3002",
                    isDark = isDark
                )
                AboutFeatureItem(
                    title = "\u5168\u90e8\u652f\u6301\u8fd0\u884c\u65f6\u5f00\u5173",
                    desc = "\u4ee5\u4e0a\u529f\u80fd\u60f3\u5f00\u5c31\u5f00\u60f3\u5173\u5c31\u5173\u2014\u2014\u867d\u7136\u6211\u4e0d\u7406\u89e3\u4f60\u4e3a\u4ec0\u4e48\u8981\u5173\u3002",
                    isDark = isDark
                )

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(1.dp)
                        .background(if (isDark) colorScheme.primary.copy(alpha = 0.12f) else RazerColors.PinkBorder)
                )

                Text(
                    text = "\u514d\u8d23\u58f0\u660e\uff08\u8ba4\u771f\u8138\uff09",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    color = RazerColors.Danger
                )
                Text(
                    text = "\u672c\u4ea7\u54c1\u57fa\u4e8e KernelSU \u4e8c\u6b21\u5f00\u53d1\uff0c\u95f2\u6687\u4e4b\u4f5c\uff0c\u5f00\u53d1\u5468\u671f\u6574\u6574\u4e00\u5929\u3002\n\n" +
                            "\u00b7 \u4e0d\u4fdd\u8bc1\u6ca1\u6709 bug\uff0c\u4f46\u76ee\u524d\u6211\u8fd8\u6ca1\u9047\u5230\n" +
                            "\u00b7 \u4e0d\u4fdd\u8bc1\u9002\u914d\u6240\u6709\u8bbe\u5907\u6240\u6709\u573a\u666f\n" +
                            "\u00b7 \u53d1\u73b0\u95ee\u9898\u6b22\u8fce\u53cd\u9988\uff0c\u4fee\u4e0d\u4fee\u770b\u5fc3\u60c5\u2014\u2014\u5f00\u73a9\u7b11\u7684\uff0c\u5c3d\u91cf\u4fee\n" +
                            "\u00b7 \u4f7f\u7528\u98ce\u9669\u81ea\u8d1f\uff0c\u51fa\u4e86\u4e8b\u6211\u53ea\u8d1f\u8d23\u540c\u60c5\u4f60",
                    fontSize = 12.sp,
                    color = textDim,
                    lineHeight = 18.sp
                )

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(accent)
                        .clickable { onDismiss() }
                        .padding(vertical = 10.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "\u77e5\u9053\u4e86",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.Black
                    )
                }
            }
        }
    }
}

@Composable
private fun AboutFeatureItem(title: String, desc: String, isDark: Boolean) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(
                if (isDark) colorScheme.primary.copy(alpha = 0.06f)
                else RazerColors.PinkElevated
            )
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(
            text = title,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = RazerColors.Green
        )
        Text(
            text = desc,
            fontSize = 12.sp,
            color = colorScheme.outline,
            lineHeight = 16.sp
        )
    }
}
