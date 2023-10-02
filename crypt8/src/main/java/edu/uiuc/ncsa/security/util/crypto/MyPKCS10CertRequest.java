package edu.uiuc.ncsa.security.util.crypto;

import java.security.PublicKey;

/**
 * This fronts a PKCS 10 certification request. Since there are many implementations, some much
 * more finicky than others, this will let users choose which they should use.
 * <p>Created by Jeff Gaynor<br>
 * on 10/16/13 at  10:46 AM
 */
public abstract class MyPKCS10CertRequest {
    /**
     * Get this as a DER encoded byte array.
     */
    abstract public byte[] getEncoded();

    /**
     * Return the current public key
     */
    abstract public PublicKey getPublicKey();

    /**
     * Get the CN (Common Name) for this cert request.
     */
    abstract public String getCN();
}
