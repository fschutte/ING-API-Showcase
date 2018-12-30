package nl.brachio.ingapi.ktoringshowcase

import com.typesafe.config.ConfigFactory
import io.ktor.config.HoconApplicationConfig
import io.ktor.util.KtorExperimentalAPI

// The config HoconApplicationConfig seems to be experimental, so I isolated it and gave it the appropriate annotation
//  Also, to get rid of compiler warnings, I've added this compiler flag in maven: -Xuse-experimental=kotlin.Experimental

@UseExperimental(KtorExperimentalAPI::class)
class Config {
    private val config = HoconApplicationConfig(ConfigFactory.load())

    val signkey = config.property("ing.signkey").getString()
    val clientId = config.property("ing.clientId").getString()
    val keystorePath = config.property("ing.keystore.path").getString()
    val keystorePassword = config.property("ing.keystore.storepassword").getString()
    val keyPassword = config.property("ing.keystore.keypassword").getString()
}