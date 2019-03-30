package nl.brachio.ingapi.vanillajava12ingshowcase;

import lombok.Data;
import lombok.Getter;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Getter
public class Config {
    private final String signkey;
    private final String clientId;
    private final String keystorePath;
    private final String keystorePassword;
    private final String keyPassword;

    Config() {
        // read props
        Properties props = new Properties();
        try (InputStream is = Config.class.getClassLoader().getResourceAsStream("config.properties")) {
            if (is == null) throw new IOException(("Could not open config.properties"));
            props.load(is);
        } catch (Exception e) {
            throw new RuntimeException("Problem reading properties file: " + e);
        }

        clientId = props.getProperty("clientId");
        signkey = props.getProperty("signkey");
        keystorePath = props.getProperty("keystore.path");
        keystorePassword = props.getProperty("keystore.storepassword");
        keyPassword = props.getProperty("keystore.keypassword");

    }
}
