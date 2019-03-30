package nl.brachio.ingapi.vanillajava12ingshowcase;

import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

@Slf4j
public class SecurityUtil {

    public static PrivateKey readPrivateKeyFile(String fileName) {
        try {
            var path = Paths.get(fileName);
            System.out.println("Reading private key file "+path.toAbsolutePath());
            var lines = Files.readAllLines(path);
            var pem = lines.stream().limit(lines.size()-1).skip(1).collect(Collectors.joining(""));
            var encoded = Base64.getDecoder().decode(pem);
            var spec = new PKCS8EncodedKeySpec(encoded);
            var kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);

        } catch (GeneralSecurityException | IOException e) {
            throw new UnexpectedSecurityException("Problem extracting private key from PEM: "+e, e);
        }
    }

    // convert key in pem format to a java public key
    public static PublicKey readPublicKeyFile(String fileName) {
        try {
            var path = Paths.get(fileName);
            System.out.println("Reading public key file "+path.toAbsolutePath());
            var lines = Files.readAllLines(path);
            var pem = lines.stream().limit(lines.size()-1).skip(1).collect(Collectors.joining(""));
            var encoded = Base64.getDecoder().decode(pem);
            var spec = new X509EncodedKeySpec(encoded);
            var kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);

        } catch (GeneralSecurityException | IOException e) {
            throw new UnexpectedSecurityException("Problem extracting public key from PEM: "+e, e);
        }
    }

    public static String createSignature(String stringToSign, PrivateKey privateKey) {
        try {
            byte[] data = stringToSign.getBytes(StandardCharsets.UTF_8);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(data);
            byte[] signatureBytes = sig.sign();
            String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);
            log.debug("Signature = {}", base64Signature);


            return base64Signature;
        } catch (GeneralSecurityException e) {
            throw new UnexpectedSecurityException("Problem creating signature: "+e, e);
        }
    }

    public static String createDigest(String text) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return "SHA-256=" + Base64.getEncoder().encodeToString(hash);
        } catch (GeneralSecurityException e) {
            throw new UnexpectedSecurityException("Problem creating digest: "+e, e);
        }
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] signature, String stringToVerify) {
        try {
            byte[] data = stringToVerify.getBytes(StandardCharsets.UTF_8);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new UnexpectedSecurityException("Problem verifying signature: "+e, e);
        }

    }


}
