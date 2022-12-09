package dawang.KernelSU.Core.ui.component

import androidx.compose.runtime.Composable
import dawang.KernelSU.Core.Natives

@Composable
fun KsuIsValid(
    content: @Composable () -> Unit
) {
    val isManager = Natives.isManager
    val ksuVersion = if (isManager) Natives.version else null

    if (ksuVersion != null) {
        content()
    }
}
