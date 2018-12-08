package nl.brachio.ingapi.vertxshowcase

import io.vertx.core.logging.LoggerFactory
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


object SecurityUtil {

  private val logger = LoggerFactory.getLogger(this.javaClass.name)

  // pem to private key
  fun readPrivateKeyFile(fileName: String): PrivateKey {
    val path = Paths.get(fileName)
    logger.info("Reading private key file ${path.toAbsolutePath()}")
    val lines = Files.readAllLines(path)
    val pem = lines.dropLast(1).drop(1).joinToString("")
    val encoded = Base64.getDecoder().decode(pem)
    val spec = PKCS8EncodedKeySpec(encoded)
    val kf = KeyFactory.getInstance("RSA")
    return kf.generatePrivate(spec)
  }

  // pem to public key
  fun readPublicKeyFile(fileName: String): PublicKey {
    val path = Paths.get(fileName)
    logger.info("Reading public key file ${path.toAbsolutePath()}")
    val lines = Files.readAllLines(path)
    val pem = lines.dropLast(1).drop(1).joinToString("")
    val encoded = Base64.getDecoder().decode(pem)
    val spec = X509EncodedKeySpec(encoded)
    val kf = KeyFactory.getInstance("RSA")
    val pubKey = kf.generatePublic(spec)
    return pubKey
  }


  fun createSignature(stringToSign: String, privateKey: PrivateKey): String {
    val data = stringToSign.toByteArray(charset("UTF8"))
    val sig = Signature.getInstance("SHA256withRSA")
    sig.initSign(privateKey)
    sig.update(data)
    val signatureBytes = sig.sign()
    val base64Signature = Base64.getEncoder().encodeToString(signatureBytes)
    return base64Signature
  }

  fun createDigest(text: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(text.toByteArray(StandardCharsets.UTF_8))
    return "SHA-256=" + Base64.getEncoder().encodeToString(hash)
  }

  fun verifySignature(publicKey: PublicKey, signature: ByteArray, stringToVerify: String): Boolean {
    val data = stringToVerify.toByteArray(charset("UTF8"))
    val sig = Signature.getInstance("SHA256withRSA")
    sig.initVerify(publicKey)
    sig.update(data)
    val verify = sig.verify(signature)
    return verify
  }
}
