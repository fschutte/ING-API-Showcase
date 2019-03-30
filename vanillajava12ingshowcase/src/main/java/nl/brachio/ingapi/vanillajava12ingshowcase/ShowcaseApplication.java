package nl.brachio.ingapi.vanillajava12ingshowcase;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static nl.brachio.ingapi.vanillajava12ingshowcase.SecurityUtil.*;

/**
 * Basic example that uses the http client that was added to Java 11.
 * Note however that Java 11 did not allow changing some header fields like e.g. the Date field
 * and for this API the Date field needed to be overridden so we had to wait till Java 12 came out (March 2019).
 *
 * The api.ing.com Showcase example is used. It first gets the oauth (client_credentials) token, and then gets the so-called greetings.
 * It verifies the response according to the rules as specified by ING.
 * For tracing http traffic, use system variables: -Djdk.httpclient.HttpClient.log=requests,headers
 */
@Slf4j
public class ShowcaseApplication {

    private static final String ING_API_BASE_URL = "https://api.ing.com";
    private static final DateTimeFormatter DATEFORMATTER = DateTimeFormatter.ofPattern("E, dd MMM yyyy HH:mm:ss O", Locale.US);

    private final String clientId;
    private final PrivateKey signKey;
    private final HttpClient client;

    @Value
    private static class Registration {
        private final String accessToken;
        private final PublicKey serverPublicKey;
    }


    public static void main(String[] args) {
        new ShowcaseApplication(new Config()).execute();
    }


    private static HttpClient initHttpClient(String keystorePath, String keystorePassword, String keyPassword) {
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fis, keystorePassword.toCharArray());
            log.debug("Loaded keystore {}", keyStore);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyPassword.toCharArray());
            log.debug("Initialized keyManagerFactory");

            // just use default trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore)null);
            log.debug("Initialized trustManagerFactory");

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            log.debug("Initialized sslContext {}", sslContext);

            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .build();

        } catch (Exception e) {
            throw new RuntimeException("Problem creating ssl context: " + e);
        }
    }

    private static Registration responseToRegistration(HttpResponse<String> resp) {
        try {
            String body = resp.body();
            JSONObject json = new JSONObject(body);
            JSONObject key = json.getJSONArray("keys").getJSONObject(0);
            log.debug("Extracted key from json response = {}", key);
            String accessToken = json.getString("access_token");
            log.debug("Extracted accessToken = {}", accessToken);

            PublicKey serverPublicKey = RSAKey.parse(key.toString()).toPublicKey();
            log.debug("serverPublicKey = {}", serverPublicKey);

            return new Registration(accessToken, serverPublicKey);
        } catch (Exception e) {
            throw new RuntimeException("Response could not be transformed in Registration object", e);
        }
    }


    public ShowcaseApplication(Config config) {
        clientId = config.getClientId();
        signKey = readPrivateKeyFile(config.getSignkey());
        client = initHttpClient(config.getKeystorePath(), config.getKeystorePassword(), config.getKeyPassword());
    }

    public void execute() {
        callOauth()
                .thenApply(ShowcaseApplication::responseToRegistration)
                .thenCompose(this::callGreeting)
                .whenComplete((greeting,t) -> {
                    log.info("*** GOT GREETING:\n{}", greeting);
                })
                .join();
    }

    private CompletableFuture<HttpResponse<String>> callOauth() {

        var httpMethod = "POST";
        var pathWithoutQuery = "/oauth2/token";
        var pathWithQuery = pathWithoutQuery + "";
        var requestBody = "grant_type=client_credentials&scope=greetings%3Aview";
        var date = ZonedDateTime.now(ZoneOffset.UTC).format(DATEFORMATTER);
        var reqId = UUID.randomUUID().toString();
        var digest = createDigest(requestBody);

        var toSign = String.format("(request-target): %s %s\ndate: %s\ndigest: %s\nx-ing-reqid: %s"
                , httpMethod.toLowerCase(), pathWithoutQuery, date, digest, reqId);

        log.debug("String toSign:\n{}", toSign);

        var signature = createSignature(toSign, signKey);
        log.debug("Signature=\n{}", signature);

        String authorizationHeader = String.format("Signature keyId=\"%s\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"%s\"",
                clientId, signature);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(ING_API_BASE_URL + pathWithQuery))
                .method(httpMethod, HttpRequest.BodyPublishers.ofString(requestBody))
                .header("Content-type", "application/x-www-form-urlencoded")
                .header("Digest", digest)
                .header("Date", date)  // in Java11: gives illegalargument because Date is restricted. -> but it works in Java12
                .header("X-ING-ReqID", reqId)
                .header("Authorization", authorizationHeader)
                .build();


        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .whenComplete((resp, t) -> {
                    log.info("{} {} -> Received http status: {}\nbody={}",
                            httpMethod, pathWithQuery, resp.statusCode(), resp.body());
                });
    }

    private CompletableFuture<String> callGreeting(Registration registration) {
        var httpMethod = "GET";
        var pathWithoutQuery = "/greetings/single";
        var pathWithQuery = pathWithoutQuery + "";
        var requestBody = "";
        var date = ZonedDateTime.now(ZoneOffset.UTC).format(DATEFORMATTER);
        var reqId = UUID.randomUUID().toString();
        var digest = createDigest(requestBody);

        var toSign = String.format("(request-target): %s %s\ndate: %s\ndigest: %s\nx-ing-reqid: %s"
                , httpMethod.toLowerCase(), pathWithoutQuery, date, digest, reqId);

        log.debug("String toSign:\n{}", toSign);

        var signature = createSignature(toSign, signKey);
        log.debug("Signature=\n{}", signature);

        String signatureHeader = String.format("keyId=\"%s\",algorithm=\"rsa-sha256\",headers=\"(request-target) date digest x-ing-reqid\",signature=\"%s\"",
                clientId, signature);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(ING_API_BASE_URL + pathWithQuery))
                .method(httpMethod, HttpRequest.BodyPublishers.ofString(requestBody))
                .header("Accept", "application/json")
                .header("Digest", digest)
                .header("Date", date)  // in Java11: gives illegalargument because Date is restricted. -> but it works in Java12
                .header("X-ING-ReqID", reqId)
                .header("Authorization", "Bearer " + registration.getAccessToken())
                .header("Signature", signatureHeader)
                .build();


        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .whenComplete((resp, t) -> {
                    log.info("{} {} -> Received http status: {}\nbody={}",
                            httpMethod, pathWithQuery, resp.statusCode(), resp.body());
                    verifyResponse(resp, registration.getServerPublicKey());

                }).thenApply(HttpResponse::body);

    }


    private void verifyResponse(HttpResponse<String> resp, PublicKey serverPublicKey) {
        HttpHeaders headers = resp.headers();

        // 1. verify digest
        String respDigest = headers.firstValue("Digest").orElse(null);
        log.debug("response   digest={}", respDigest);
        String calculatedDigest = createDigest(resp.body());
        log.debug("calculated digest={}", calculatedDigest);

        // 2. verify signature
        String respSignature = headers.firstValue("Signature").orElseThrow();
        log.debug("Signature header={}", respSignature);

        Pattern p = Pattern.compile(".*headers=\"(.+)\".*signature=\"(.+)\".*");
        Matcher m = p.matcher(respSignature);

        // if our pattern matches the string, we can try to extract our groups
        if (!m.find()) throw new RuntimeException("Headers and signature could not be extracted from Signature header");

        String sigheaders = m.group(1);
        String sig = m.group(2);
        String toVerify = Arrays.stream(sigheaders.split(" "))
                .map(h -> h.toLowerCase() + ": " + headers.firstValue(h).orElseThrow())
                .collect(Collectors.joining("\n"));


        log.debug("Server toVerify={}", toVerify);

        byte[] serverSignature = Base64.getDecoder().decode(sig);
        boolean verified = verifySignature(serverPublicKey, serverSignature, toVerify);
        log.info("***** verified: {}", verified);
    }
}
