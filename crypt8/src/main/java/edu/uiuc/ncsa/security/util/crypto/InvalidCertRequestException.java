package edu.uiuc.ncsa.security.util.crypto;

/**
 * Runtime version of an invalid cert request exception.
 * <p>Created by Jeff Gaynor<br>
 * on 1/8/14 at  10:53 AM
 */
public class InvalidCertRequestException extends CryptoException {
    public InvalidCertRequestException() {
    }

    public InvalidCertRequestException(Throwable cause) {
        super(cause);
    }

    public InvalidCertRequestException(String message) {
        super(message);
    }

    public InvalidCertRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
