package nl.brachio.ingapi.vertxshowcase

import com.nimbusds.jose.jwk.RSAKey
import io.reactivex.Single
import io.vertx.core.Future
import io.vertx.core.http.HttpMethod
import io.vertx.core.json.JsonObject
import io.vertx.core.logging.LoggerFactory
import io.vertx.core.net.PemKeyCertOptions
import io.vertx.ext.web.client.WebClientOptions
import io.vertx.reactivex.core.AbstractVerticle
import io.vertx.reactivex.core.buffer.Buffer
import io.vertx.reactivex.ext.web.client.HttpResponse
import io.vertx.reactivex.ext.web.client.WebClient
import io.vertx.reactivex.ext.web.codec.BodyCodec
import nl.brachio.ingapi.vertxshowcase.SecurityUtil.createDigest
import nl.brachio.ingapi.vertxshowcase.SecurityUtil.createSignature
import nl.brachio.ingapi.vertxshowcase.SecurityUtil.readPrivateKeyFile
import nl.brachio.ingapi.vertxshowcase.SecurityUtil.verifySignature
import java.security.PrivateKey
import java.security.PublicKey
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.*

private val ING_API_BASE_URL = "https://api.ing.com"
private val DATEFORMATTER = DateTimeFormatter.ofPattern("E, dd MMM yyyy HH:mm:ss O", Locale.US)
// cannot use DateTimeFormatter.RFC_1123_DATE_TIME gives Mon, 5 Nov 2018 21:22:52 GMT  instead of Mon, 05 Nov 2018 21:22:52 GMT
//  and that gives http status 400: {"message":"param 'Date' cannot be converted to ZonedDateTimeWithFormattedDateString: Invalid Date header format."}


data class Registration(
  val accessToken: String,
  val serverPublicKey: PublicKey
)


class MainVerticle : AbstractVerticle() {
  private val logger = LoggerFactory.getLogger(this.javaClass.name)

  private val clientId: String by lazy { config().getString("clientId") }
  private val signKey: PrivateKey by lazy { readPrivateKeyFile(config().getString("signkey")) }

  private val webClient: WebClient by lazy {
    WebClient.create(vertx,
      WebClientOptions()
        .setLogActivity(true) // logs extra network traffic (netty)
        .setPemKeyCertOptions(PemKeyCertOptions()
          .setKeyPath(config().getString("keypath"))
          .setCertPath(config().getString("certpath"))
        )
    )
  }


  override fun start(startFuture: Future<Void>) {

    logger.info("start()")
    callOauth()
      .map(this::responseToRegistration)
      .flatMap(this::callGreetings)
      .subscribe({ json ->
        logger.info("*** GOT GREETING: ${json.getString("message")}")
        startFuture.complete()
      }, { t ->
        t.printStackTrace()
        startFuture.fail(t)
      })
  }


  fun callOauth(): Single<HttpResponse<JsonObject>> {
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
      .requestAbs(httpMethod, ING_API_BASE_URL + path)
      .putHeader("Content-Type", "application/x-www-form-urlencoded")
      .putHeader("Digest", digest)
      .putHeader("Date", date)
      .putHeader("X-ING-ReqID", reqId)
      .putHeader("Authorization", "Signature keyId=\"$clientId\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"$signature\"")
      .`as`(BodyCodec.jsonObject())
      .rxSendBuffer(Buffer.buffer(body))
      .doOnSuccess { resp ->
        logger.info("Response oauth = \nStatus ${resp.statusCode()}, ${resp.body()}")
      }
  }


  fun responseToRegistration(resp: HttpResponse<JsonObject>): Registration {
    val json = resp.body()
    val accessToken = json.getString("access_token")
    val key = json.getJsonArray("keys").getJsonObject(0)
    val serverPublicKey = RSAKey.parse(key.encode()).toPublicKey()
    logger.debug("Found access token and server public key in response. \nToken=$accessToken \nKey=$serverPublicKey")
    return Registration(accessToken, serverPublicKey)
  }


  fun callGreetings(registration: Registration): Single<JsonObject> {
    val httpMethod = HttpMethod.GET
    val path = "/greetings/single"
    val pathWithoutQuery = path.substringBefore("?")
    val body = ""
    val date = ZonedDateTime.now(ZoneOffset.UTC).format(DATEFORMATTER)
    val reqId = UUID.randomUUID().toString()
    val digest = createDigest(body)

    val toSign = "(request-target): %s %s\ndate: %s\ndigest: %s\nx-ing-reqid: %s"
      .format(httpMethod.name.toLowerCase(), pathWithoutQuery, date, digest, reqId)

    logger.debug("String toSign:\n$toSign")

    val signature = createSignature(toSign, signKey)
    logger.debug("Signature=\n$signature")

    val httpRequest = webClient
      .requestAbs(httpMethod, ING_API_BASE_URL + path)
      .putHeader("Accept", "application/json")
      .putHeader("Digest", digest)
      .putHeader("Date", date)
      .putHeader("X-ING-ReqID", reqId)
      .putHeader("Authorization", "Bearer " + registration.accessToken)
      .putHeader("Signature", "keyId=\"$clientId\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"$signature\"")
      .`as`(BodyCodec.string())

    return httpRequest.rxSend()
      .doOnSuccess { resp ->
        logger.info("Response greeting = \nStatus ${resp.statusCode()}, ${resp.body()}")
        verifyResponse(resp, registration.serverPublicKey)
      }
      .map { resp ->
        JsonObject(resp.body())
      }
  }


  private fun verifyResponse(resp: HttpResponse<String>, serverPublicKey: PublicKey) {
    val respBody = resp.body() ?: ""
    val headers = resp.headers()

    // 1. verify digest
    val respDigest = headers.get("Digest")
    logger.debug("response   digest=$respDigest")
    val calculatedDigest = createDigest(respBody)
    logger.debug("calculated digest=$calculatedDigest")

    // 2. verify signature
    val respSignature = headers.get("Signature")
    logger.debug("Signature header = $respSignature")
    val (sigheaders, sig) = """.*headers="(.+)".*signature="(.+)".*""".toRegex().find(respSignature!!)!!.destructured
    logger.debug("Extracted headers = $sigheaders")
    logger.debug("Extracted signature = $sig")

    val toVerify = sigheaders.split(" ")
      .map { h -> "${h.toLowerCase()}: ${headers.get(h)}" }
      .joinToString("\n")

//            val serverReqId = headers.get("X-ING-ReqID")
//            val serverRespId = headers.get("X-ING-Response-ID")
//            val toVerify = "x-ing-reqid: $serverReqId\nx-ing-response-id: $serverRespId"


    logger.debug("Server toVerify=\n$toVerify")

    val serverSignature = Base64.getDecoder().decode(sig)
    val b = verifySignature(serverPublicKey, serverSignature, toVerify)
    logger.info("***** verified: $b")
  }

}
