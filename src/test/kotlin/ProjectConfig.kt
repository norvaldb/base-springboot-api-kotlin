import io.kotest.core.config.AbstractProjectConfig
import io.kotest.extensions.allure.AllureTestReporter

class ProjectConfig : AbstractProjectConfig() {
    @Suppress("OVERRIDE_DEPRECATION")
    override fun listeners() = listOf(AllureTestReporter())
}
