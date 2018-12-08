package nl.brachio.ingapi.springingshowcase

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "ingapi")
class Config {
    lateinit var keypath: String
    lateinit var certpath: String
    lateinit var signkey: String
    lateinit var clientId: String
}
