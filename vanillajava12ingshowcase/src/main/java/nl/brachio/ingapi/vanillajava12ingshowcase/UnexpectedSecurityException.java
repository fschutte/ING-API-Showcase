package nl.brachio.ingapi.vanillajava12ingshowcase;

public class UnexpectedSecurityException extends RuntimeException {
    public UnexpectedSecurityException() {
        super();
    }

    public UnexpectedSecurityException(String message) {
        super(message);
    }

    public UnexpectedSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnexpectedSecurityException(Throwable cause) {
        super(cause);
    }

    protected UnexpectedSecurityException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
