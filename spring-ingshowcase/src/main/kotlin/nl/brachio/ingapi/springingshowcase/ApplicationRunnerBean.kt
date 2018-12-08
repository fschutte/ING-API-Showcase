package nl.brachio.ingapi.springingshowcase

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.jwk.RSAKey
import io.netty.handler.ssl.SslContextBuilder
import mu.KotlinLogging
import nl.brachio.ingapi.springingshowcase.SecurityUtil.createDigest
import nl.brachio.ingapi.springingshowcase.SecurityUtil.createSignature
import nl.brachio.ingapi.springingshowcase.SecurityUtil.readPrivateKeyFile
import nl.brachio.ingapi.springingshowcase.SecurityUtil.verifySignature
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.http.HttpMethod
import org.springframework.http.ResponseEntity
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.ClientCodecConfigurer
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.reactive.function.client.ExchangeStrategies
import org.springframework.web.reactive.function.client.WebClient
import reactor.core.publisher.Mono
import reactor.netty.http.client.HttpClient
import java.io.File
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.function.Consumer

private val ING_API_BASE_URL = "https://api.ing.com"
private val DATEFORMATTER = DateTimeFormatter.ofPattern("E, dd MMM yyyy HH:mm:ss O", Locale.US)
// cannot use DateTimeFormatter.RFC_1123_DATE_TIME gives Mon, 5 Nov 2018 21:22:52 GMT  instead of Mon, 05 Nov 2018 21:22:52 GMT
//  and that gives http status 400: {"message":"param 'Date' cannot be converted to ZonedDateTimeWithFormattedDateString: Invalid Date header format."}

private val logger = KotlinLogging.logger {}

internal data class Registration(
  val accessToken: String,
  val serverPublicKey: PublicKey
)


// WebClient.Builder is autowired by default by Spring
@Component
class ApplicationRunnerBean(val config: Config, val webClientBuilder: WebClient.Builder) : ApplicationRunner {

  private val objectMapper = ObjectMapper()
  private val clientId: String by lazy { config.clientId }
  private val signKey: PrivateKey by lazy { readPrivateKeyFile(config.signkey) }

  private val webClient: WebClient by lazy {
    val sslContext = SslContextBuilder.forClient()
      .keyManager(
        File(config.certpath),
        File(config.keypath))
      .build()

    val httpClient = HttpClient.create().secure { s -> s.sslContext(sslContext) }
    val httpConnector = ReactorClientHttpConnector(httpClient)

    // trace http request/response
    val consumer = Consumer<ClientCodecConfigurer> { configurer ->
      configurer.defaultCodecs().enableLoggingRequestDetails(true)
    }

    webClientBuilder
      .clientConnector(httpConnector)
      .baseUrl(ING_API_BASE_URL)
      .exchangeStrategies(ExchangeStrategies.builder().codecs(consumer).build())
      .build()

  }


  override fun run(arg0: ApplicationArguments) {

    val doneSignal = CountDownLatch(1)

    logger.info("start()")
    callOauth()
      .map(this::responseToRegistration)
      .flatMap(this::callGreetings)
      .subscribe({ json ->
        logger.info("*** GOT GREETING: ${json["message"].textValue()}")
        doneSignal.countDown()
      }, { err ->
        err.printStackTrace()
        doneSignal.countDown()
      })

    doneSignal.await()
  }


  private fun callOauth(): Mono<ResponseEntity<JsonNode>> {
    val httpMethod = HttpMethod.POST
    val path = "/oauth2/token"
    val pathWithoutQuery = path.substringBefore("?")
    val body = "grant_type=client_credentials&scope=greetings%3Aview"
    val date = ZonedDateTime.now(ZoneOffset.UTC).format(DATEFORMATTER)
    val reqId = UUID.randomUUID().toString()
    val digest = createDigest(body)

    val toSign = "(request-target): %s %s\ndate: %s\ndigest: %s\nx-ing-reqid: %s"
      .format(httpMethod.name.toLowerCase(), pathWithoutQuery, date, digest, reqId)

    logger.debug("String toSign:\n$toSign")

    val signature = createSignature(toSign, signKey)
    logger.debug("Signature=\n$signature")

    return webClient
      .method(httpMethod)
      .uri(path)
      .header("Content-Type", "application/x-www-form-urlencoded")
      .header("Digest", digest)
      .header("Date", date)
      .header("X-ING-ReqID", reqId)
      .header("Authorization", "Signature keyId=\"$clientId\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"$signature\"")
      .body(BodyInserters.fromObject(body))
      .exchange()
      .flatMap { resp ->
        println("ClientResponse: $resp")
        resp.toEntity(JsonNode::class.java)
      }
  }

  private fun responseToRegistration(resp: ResponseEntity<JsonNode>): Registration {
    val json = resp.body ?: throw RuntimeException("no body found")
    val accessToken = json["access_token"].textValue()
    val key = json["keys"][0]
    val serverPublicKey = RSAKey.parse(key.toString()).toPublicKey()
    logger.debug("Found access token and server public key in response. \nToken=$accessToken \nKey=$serverPublicKey")
    return Registration(accessToken, serverPublicKey)
  }


  private fun callGreetings(registration: Registration): Mono<JsonNode> {
    val httpMethod = HttpMethod.GET
    val path = "/greetings/single"
    val pathWithoutQuery = path.substringBefore("?")
    val body = ""
    val date = ZonedDateTime.now(ZoneOffset.UTC).format(DATEFORMATTER)
    val reqId = UUID.randomUUID().toString().toUpperCase()
    val digest = createDigest(body)

    val toSign = "(request-target): %s %s\ndate: %s\ndigest: %s\nx-ing-reqid: %s"
      .format(httpMethod.name.toLowerCase(), pathWithoutQuery, date, digest, reqId)

    println("String toSign:\n$toSign")

    val signature = createSignature(toSign, signKey)
    println("Signature=\n$signature")

    return webClient
      .method(httpMethod)
      .uri(path)
      .header("Accept", "application/json")
      .header("Digest", digest)
      .header("Date", date)
      .header("X-ING-ReqID", reqId)
      .header("Authorization", "Bearer ${registration.accessToken}")
      .header("Signature", "keyId=\"$clientId\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"$signature\"")
      .exchange()
      .flatMap { resp ->
        println("ClientResponse: $resp")
        resp.toEntity(String::class.java)
      }
      .doOnSuccess { resp ->
        logger.info("Response greeting = \nStatus ${resp.statusCode}, ${resp.body}")
        verifyResponse(resp, registration.serverPublicKey)

      }
      .map { respEntity ->
        objectMapper.readTree(respEntity.body)
      }


  }

  private fun verifyResponse(resp: ResponseEntity<String>, serverPublicKey: PublicKey) {
    val respBody = resp.body ?: ""
    val headers = resp.headers

    // 1. verify digest
    val respDigest = headers.getFirst("Digest")
    logger.debug("response   digest=$respDigest")
    val calculatedDigest = createDigest(respBody)
    logger.debug("calculated digest=$calculatedDigest")

    // 2. verify signature
    val respSignature = headers.getFirst("Signature")
    logger.debug("Signature header = $respSignature")
    val (sigheaders, sig) = """.*headers="(.+)".*signature="(.+)".*""".toRegex().find(respSignature!!)!!.destructured
    logger.debug("Extracted headers = $sigheaders")
    logger.debug("Extracted signature = $sig")

    val toVerify = sigheaders.split(" ")
      .map { h -> "${h.toLowerCase()}: ${headers.getFirst(h)}" }
      .joinToString("\n")

//              val serverReqId = resp.headers.getFirst("X-ING-ReqID")
//              val serverRespId = resp.headers.getFirst("X-ING-Response-ID")
//              val toVerify = String.format("x-ing-reqid: %s\nx-ing-response-id: %s", serverReqId, serverRespId)

    logger.debug("Server toVerify=\n$toVerify")

    val serverSignature = Base64.getDecoder().decode(sig)
    val b = verifySignature(serverPublicKey, serverSignature, toVerify)
    logger.info("***** verified: $b")
  }
}
