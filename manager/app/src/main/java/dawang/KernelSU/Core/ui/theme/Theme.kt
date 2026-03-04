package dawang.KernelSU.Core.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.Color
import dawang.KernelSU.Core.ui.webui.MonetColorsProvider.UpdateCss
import top.yukonga.miuix.kmp.theme.ColorSchemeMode
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.ThemeController

@Composable
fun KernelSUTheme(
    colorMode: Int = 0,
    keyColor: Color? = null,
    content: @Composable () -> Unit
) {
    val isDark = isSystemInDarkTheme()
    // 浅色模式默认使用品牌深青种子，用户自定义强调色优先
    val defaultLightKey = Color(0xFF0F8F7A)
    val lightKey = keyColor ?: defaultLightKey
    val controller = when (colorMode) {
        1 -> ThemeController(ColorSchemeMode.MonetLight, keyColor = lightKey)
        2 -> ThemeController(ColorSchemeMode.Dark)
        3 -> ThemeController(
            if (isDark) ColorSchemeMode.MonetDark else ColorSchemeMode.MonetLight,
            keyColor = if (isDark) keyColor else lightKey,
        )
        4 -> ThemeController(
            ColorSchemeMode.MonetLight,
            keyColor = lightKey,
        )
        5 -> ThemeController(
            ColorSchemeMode.MonetDark,
            keyColor = keyColor,
        )
        else -> ThemeController(
            if (isDark) ColorSchemeMode.Dark else ColorSchemeMode.MonetLight,
            keyColor = lightKey,
        )
    }
    return MiuixTheme(
        controller = controller,
        content = {
            UpdateCss()
            content()
        }
    )
}

@Composable
@ReadOnlyComposable
fun isInDarkTheme(themeMode: Int): Boolean {
    val isDark = isSystemInDarkTheme()
    return when (themeMode) {
        1 -> false  // Light
        2, 5 -> true  // Dark, Monet Dark
        else -> isDark  // System, Monet System
    }
}
