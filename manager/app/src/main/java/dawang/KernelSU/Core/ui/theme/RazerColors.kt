package dawang.KernelSU.Core.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * Razer / NVIDIA inspired color palette.
 * Matches the CSS variables defined in ui_design.html.
 */
object RazerColors {
    // ══ Core Green System ══
    val Green       = Color(0xFF44D62C)   // Razer signature green
    val GreenDim    = Color(0xFF3AB826)
    val GreenDark   = Color(0xFF2A8A1B)
    val GreenBorder = Color(0x4044D62C)   // ~25% alpha
    val GreenBg     = Color(0x0F44D62C)   // ~6% alpha
    val GreenBgH    = Color(0x1F44D62C)   // ~12% alpha
    val GreenSubtle = Color(0x0844D62C)   // ~3% alpha

    // ══ Backgrounds ══
    val Black       = Color(0xFF050505)
    val BgBase      = Color(0xFF0C0C0C)
    val BgCard      = Color(0xFF141414)
    val BgElevated  = Color(0xFF1C1C1C)
    val BgHover     = Color(0xFF1F1F1F)
    val Border      = Color(0xFF1E1E1E)

    // ══ Text ══
    val T100        = Color(0xFFF2F2F2)
    val T90         = Color(0xFFD4D4D4)
    val T60         = Color(0xFF888888)
    val T40         = Color(0xFF555555)
    val T25         = Color(0xFF363636)

    // ══ Danger ══
    val Danger       = Color(0xFFFF3B3B)
    val DangerBg     = Color(0x0FFF3B3B)
    val DangerBorder = Color(0x33FF3B3B)

    // ══ Status card: dark-green gradient background ══
    val StatusCardBg     = Color(0xFF0A1A0D)
    val StatusCardBorder = Color(0x4044D62C)

    // ══ Soft Pink (少女色 Light theme) ══
    val PinkBg       = Color(0xFFFFEAEF)   // 页面背景
    val PinkCard     = Color(0xFFFFF5F7)   // 卡片背景
    val PinkElevated = Color(0xFFFFF0F3)   // 高亮元素
    val PinkBorder   = Color(0xFFFFC8D4)   // 边框/分割线
}
