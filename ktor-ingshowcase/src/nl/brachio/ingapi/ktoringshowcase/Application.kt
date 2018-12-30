package nl.brachio.ingapi.ktoringshowcase

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.nimbusds.jose.jwk.RSAKey
import io.ktor.client.HttpClient
import io.ktor.client.call.typeInfo
import io.ktor.client.engine.apache.Apache
import io.ktor.client.features.feature
import io.ktor.client.features.json.GsonSerializer
import io.ktor.client.features.json.JsonFeature
import io.ktor.client.features.json.defaultSerializer
import io.ktor.client.features.json.serializer.KotlinxSerializer
import io.ktor.client.features.logging.LogLevel
import io.ktor.client.features.logging.Logging
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.url
import io.ktor.client.response.HttpResponse
import io.ktor.client.response.readText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.content.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.json
import kotlinx.serialization.typeTokenOf
import mu.KotlinLogging
import nl.brachio.ingapi.ktoringshowcase.SecurityUtil.createDigest
import nl.brachio.ingapi.ktoringshowcase.SecurityUtil.createSignature
import nl.brachio.ingapi.ktoringshowcase.SecurityUtil.readPrivateKeyFile
import org.apache.http.ssl.SSLContexts
import java.io.File
import java.net.URL
import java.security.PublicKey
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*

// We don't need a server in our application; still we want to use Ktor goodies like the httpClient.
// For this I simply use a normal main function and discard the server Engines..
//fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)


data class Registration(
    val accessToken: String,
    val serverPublicKey: PublicKey
)


private val ING_API_BASE_URL = "https://api.ing.com"
private val DATEFORMATTER = DateTimeFormatter.ofPattern("E, dd MMM yyyy HH:mm:ss O", Locale.US)

private val logger = KotlinLogging.logger {}

private val config = Config()
private val signKey = readPrivateKeyFile(config.signkey)
private val clientId = config.clientId
private val client: HttpClient by lazy {
    HttpClient(Apache) {
        engine {
            sslContext = SSLContexts.custom()
                .loadKeyMaterial(
                    File(config.keystorePath),
                    config.keystorePassword.toCharArray(),
                    config.keyPassword.toCharArray()
                )
                .build()
        }
        install(JsonFeature) {
            serializer = GsonSerializer {
                setLenient()
            }
        }
        install(Logging) {
            // nice feature: set LogLevel to INFO, HEADERS or BODY for useful tracing
            level = LogLevel.NONE
        }
    }
}

fun main(args: Array<String>) {
    logger.info("start()")

    runBlocking {
        val oauthResponse = callOauth()
        logger.info("OAuth response status = ${oauthResponse.status}")
        if (oauthResponse.status.value != 200) {
            logger.error(oauthResponse.readText())
            logger.error("Response body: ${oauthResponse.readText()}")
            return@runBlocking
        }

        val registration = responseToRegistration(oauthResponse)

        val greetingsResponse = callGreetings(registration)
        logger.info("Greetings response status = ${greetingsResponse.status}")
        if (greetingsResponse.status.value != 200) {
            logger.error("Response body: ${greetingsResponse.readText()}")
            return@runBlocking
        }

        // somehow the  defaultSerializer() gives the KotlinXSerializer instead of the gson one, so we use an alternative method
        val serializer = client.feature(JsonFeature)!!.serializer
        val json = serializer.read(typeInfo<JsonObject>(), greetingsResponse) as JsonObject
        // This line does pretty much the same
        // val json = JsonParser().parse(greetingsResponse.readText()).asJsonObject

        logger.info("*** GOT GREETING: ${json["message"].asString}")
    }
}



private suspend fun responseToRegistration(resp: HttpResponse): Registration {
    val json = JsonParser().parse(resp.readText()).asJsonObject
    val accessToken = json["access_token"].asString
    val key = json.getAsJsonArray("keys")[0]
    val serverPublicKey = RSAKey.parse(key.toString()).toPublicKey()
    logger.debug("Found access token and server public key in response. \nToken=$accessToken \nKey=$serverPublicKey")
    return Registration(accessToken, serverPublicKey)
}

private suspend fun callOauth(): HttpResponse {
    val httpMethod = HttpMethod.Post
    val pathWithoutQuery = "/oauth2/token"
    val pathWithQuery = pathWithoutQuery + ""
    val requestBody = "grant_type=client_credentials&scope=greetings%3Aview"
    val date = ZonedDateTime.now(ZoneOffset.UTC).format(DATEFORMATTER)
    val reqId = UUID.randomUUID().toString()
    val digest = createDigest(requestBody)

    val toSign = "(request-target): %s %s\ndate: %s\ndigest: %s\nx-ing-reqid: %s"
        .format(httpMethod.value.toLowerCase(), pathWithoutQuery, date, digest, reqId)

    logger.debug("String toSign:\n$toSign")

    val signature = createSignature(toSign, signKey)
    logger.debug("Signature=\n$signature")

    return client.request<HttpResponse> {
        url(URL(ING_API_BASE_URL + pathWithQuery))
        method = httpMethod
        body = TextContent(requestBody, contentType = ContentType.Application.FormUrlEncoded)
        header("Digest", digest)
        header("Date", date)
        header("X-ING-ReqID", reqId)
        header(
            "Authorization",
            "Signature keyId=\"$clientId\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"$signature\""
        )
    }

}


private suspend fun callGreetings(registration: Registration): HttpResponse {

    val httpMethod = HttpMethod.Get
    val pathWithoutQuery = "/greetings/single"
    val pathWithQuery = pathWithoutQuery + ""
    val requestBody = ""
    val date = ZonedDateTime.now(ZoneOffset.UTC).format(DATEFORMATTER)
    val reqId = UUID.randomUUID().toString()
    val digest = createDigest(requestBody)

    val toSign = "(request-target): %s %s\ndate: %s\ndigest: %s\nx-ing-reqid: %s"
        .format(httpMethod.value.toLowerCase(), pathWithoutQuery, date, digest, reqId)

    logger.debug("String toSign:\n$toSign")

    val signature = createSignature(toSign, signKey)
    logger.debug("Signature=\n$signature")

    return client.request<HttpResponse> {
        url(URL(ING_API_BASE_URL + pathWithQuery))
        method = httpMethod

        header("Digest", digest)
        header("Date", date)
        header("X-ING-ReqID", reqId)
        header("Authorization", "Bearer ${registration.accessToken}")
        header("Signature", "keyId=\"$clientId\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"$signature\"")

    }

}


