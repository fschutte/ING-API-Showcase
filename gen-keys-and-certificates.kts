
import sun.security.x509.*
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*

/**
 * Simple script for generating keys and certificates as needed to connect to the ING API.
 * It generates a key and certificate for signing, and a separate one for the TLS connection.
 *
 * Note that I have avoided any third party dependency in this script. It is purely based on Java standard libraries.
 *
 * This is the equivalent of the following openssl commands:
 * openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
 * and
 * openssl pkcs12 -export -out keystore.p12 -in certificate.pem -inkey key.pem -passin pass:changeme -passout pass:changeme
 */

println("Creating keys and certificates for Signing and TLS connection..")

listOf("sign", "tls").forEach { sort ->
    val keyFile = File("key-$sort.pem")
    val certFile = File("cert-$sort.pem")
    val keystoreFile = File("keystore-$sort.p12")

    val keyPair = generateKeyPair()
    val certificate = createSelfSignedCertificate(keyPair)
    keyFile.writeText(privateKeyToPem(keyPair.private))
    println("Created ${keyFile.absoluteFile}")
    certFile.writeText(certificateToPem(certificate))
    println("Created ${certFile.absoluteFile}")

    keystoreFile.outputStream().use {
        KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("myalias", keyPair.private, "changeme".toCharArray(), arrayOf(certificate))
            store(it, "changeme".toCharArray())
            println("Created ${keystoreFile.absoluteFile}")
        }
    }
}


fun generateKeyPair(): KeyPair {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    return kpg.genKeyPair()
}


// transform to base64 with begin and end line
fun publicKeyToPem(publicKey: PublicKey): String {
    val base64PubKey = Base64.getEncoder().encodeToString(publicKey.encoded)

    return "-----BEGIN PUBLIC KEY-----\n" +
            base64PubKey.replace("(.{64})".toRegex(), "$1\n") +
            "\n-----END PUBLIC KEY-----\n"
}


fun privateKeyToPem(privateKey: PrivateKey): String {
    val base64PubKey = Base64.getEncoder().encodeToString(privateKey.encoded)

    return "-----BEGIN PRIVATE KEY-----\n" +
            base64PubKey.replace("(.{64})".toRegex(), "$1\n") +
            "\n-----END PRIVATE KEY-----\n"
}


fun certificateToPem(certificate: X509Certificate): String {
    val base64PubKey = Base64.getEncoder().encodeToString(certificate.encoded)

    return "-----BEGIN CERTIFICATE-----\n" +
            base64PubKey.replace("(.{64})".toRegex(), "$1\n") +
            "\n-----END CERTIFICATE-----\n"
}


fun createSelfSignedCertificate(keyPair: KeyPair): X509Certificate {
    // inspired by https://hecpv.wordpress.com/2017/03/18/how-to-generate-x-509-certificate-in-java-1-8/

    val commonName = "INGTestAPI"
    val organizationalUnit = "Test"
    val organization = "Test"
    val country = "NL"

    val validDays = 365


    val distinguishedName = X500Name(commonName, organizationalUnit, organization, country)

    val info = X509CertInfo()

    val since = Date() // Since Now
    val until = Date(since.time + validDays * 86400000L) // Until x days (86400000 milliseconds in one day)

    val sn = BigInteger(64, SecureRandom())

    info.set(X509CertInfo.VALIDITY, CertificateValidity(since, until))
    info.set(X509CertInfo.SERIAL_NUMBER, CertificateSerialNumber(sn))
    info.set(X509CertInfo.SUBJECT, distinguishedName)
    info.set(X509CertInfo.ISSUER, distinguishedName)
    info.set(X509CertInfo.KEY, CertificateX509Key(keyPair.public))
    info.set(X509CertInfo.VERSION, CertificateVersion(CertificateVersion.V3))

    var algo = AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid)
    info.set(X509CertInfo.ALGORITHM_ID, CertificateAlgorithmId(algo))

    // Sign the cert to identify the algorithm that is used.
    var cert = X509CertImpl(info)
    cert.sign(keyPair.private, "SHA256withRSA")

    // Update the algorithm and sign again
    algo = cert.get(X509CertImpl.SIG_ALG) as AlgorithmId
    info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo)

    cert = X509CertImpl(info)
    cert.sign(keyPair.private, "SHA256withRSA")

    return cert
}
