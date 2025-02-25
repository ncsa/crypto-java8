package edu.uiuc.ncsa.security.util.crypto;

import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * A utility for doing certain security-related operations, such as creating key pairs, serializing them and deserializing them
 * to PEM formats.<br><br>. In a nutshell you can
 * <ul>
 * <li>Generate key pairs</li>
 * <Li>Read and write PKCS 8 format private keys</li>
 * <li>Read and write X509 encoded public keys</li>
 * <li>Read PKCS 1 private keys</li>
 * </ul>
 * There is no call to write in a PKCS 1 format pem; The standard encoding now for saving keys is PKCS 8.
 * <p>All methods are static and if you need something other than the defaults, set them before first use.
 * <p>Created by Jeff Gaynor<br>
 * on Jun 15, 2010 at  4:51:25 PM
 */
public class KeyUtil {

    public static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

    public static final String BEGIN_RSA_PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----";
    public static final String END_RSA_PUBLIC_KEY = "-----END RSA PUBLIC KEY-----";

    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";


    /**
     * Use a reader to ingest a PKCS 1 private key.
     * @param reader
     * @return
     * @throws Exception
     */
    public static PrivateKey fromPKCS1PEM(Reader reader) throws Exception {
        return fromPKCS1PEM(PEMFormatUtil.readerToString(reader));
    }

    /*
    From the spec: https://datatracker.ietf.org/doc/html/rfc3447#appendix-A.1.2
     An RSA private key should be represented with the ASN.1 type
   RSAPrivateKey:

      RSAPrivateKey ::= SEQUENCE {
          version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
      }

   The fields of type RSAPrivateKey have the following meanings:

    * version is the version number, for compatibility with future
      revisions of this document.  It shall be 0 for this version of the
      document, unless multi-prime is used, in which case it shall be 1.

            Version ::= INTEGER { two-prime(0), multi(1) }
               (CONSTRAINED BY
               {-- version must be multi if otherPrimeInfos present --})

    * modulus is the RSA modulus n.
    * publicExponent is the RSA public exponent e.
    * privateExponent is the RSA private exponent d.
    * prime1 is the prime factor p of n.
    * prime2 is the prime factor q of n.
    * exponent1 is d mod (p - 1).
    * exponent2 is d mod (q - 1).
    * coefficient is the CRT coefficient q^(-1) mod p.
    * otherPrimeInfos contains the information for the additional primes
      r_3, ..., r_u, in order.  It shall be omitted if version is 0 and
      shall contain at least one instance of OtherPrimeInfo if version
      is 1.
     */

    /**
     * Read a PKCS 1 format pem and return the private key.  Read the <a href="https://www.rfc-editor.org/rfc/rfc3447#page-44">RSA spec</a>
     *
     * @param pem
     * @return
     * @throws Exception
     */
    public static PrivateKey fromPKCS1PEM(String pem) throws Exception {
        byte[] bytes = PEMFormatUtil.getBodyBytes(pem, BEGIN_RSA_PRIVATE_KEY, END_RSA_PRIVATE_KEY);

        DerInputStream derReader = new DerInputStream(bytes);
        DerValue[] sequence = derReader.getSequence(0);
        // skip the version at index 0
        //  Note that getting the big integers this way automatically corrects so that the result is always positive.
        // We have do this manually in the JSONWebKeyUtil.
        BigInteger modulus = sequence[1].getBigInteger();
        BigInteger publicExp = sequence[2].getBigInteger();
        BigInteger privateExp = sequence[3].getBigInteger();
        BigInteger prime1 = sequence[4].getBigInteger();
        BigInteger prime2 = sequence[5].getBigInteger();
        BigInteger exp1 = sequence[6].getBigInteger();
        BigInteger exp2 = sequence[7].getBigInteger();
        BigInteger crtCoef = sequence[8].getBigInteger();
        RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec =
                new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(rsaPrivateCrtKeySpec);
    }

    public static PublicKey fromPublicPKCS1PEM(Reader reader) throws Exception {
        return fromPublicPKCS1PEM(PEMFormatUtil.readerToString(reader));
    }
    /*
      Reading a PKCS 1 public key using OpenSSL
      openssl rsa -RSAPublicKey_in -in pkcs1_public.pem -noout -text
     */
    public static PublicKey fromPublicPKCS1PEM(String pem) throws Exception {
        byte[] bytes = PEMFormatUtil.getBodyBytes(pem, BEGIN_RSA_PUBLIC_KEY, END_RSA_PUBLIC_KEY);

        DerInputStream derReader = new DerInputStream(bytes);
        DerValue[] sequence = derReader.getSequence(0);
        // skip the version at index 0
        //  Note that getting the big integers this way automatically corrects so that the result is always positive.
        // We have do this manually in the JSONWebKeyUtil.
        BigInteger modulus = sequence[0].getBigInteger();
        BigInteger publicExp = sequence[1].getBigInteger();
        RSAPublicKeySpec rsaPublicKeySpec =
                new RSAPublicKeySpec(modulus, publicExp);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(rsaPublicKeySpec);
    }

    /**
     * Ingest a keypair that has been encoded in PKCS 1 format using a reader.
     * @param r
     * @return
     * @throws Exception
     */
    public static KeyPair keyPairFromPKCS1(Reader r) throws Exception {
        return keyPairFromPKCS1(PEMFormatUtil.readerToString(r));
    }

    /**
     * Verifies that a given keypair is correct, i.e., that the public and private keys
     * are in fact paired correctly.<br/><br/>
     * <b>N.B:</b> A positive result means they are <i>most likely</i> correct. A failure
     * means they most certainly do not match.
     *
     * @param keyPair
     * @return
     */
    public static boolean validateKeyPair(KeyPair keyPair) throws Exception {
        return validateKeyPair(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * See {@link #validateKeyPair(KeyPair)}
     *
     * @param publicKey
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static boolean validateKeyPair(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        byte[] challenge = new byte[10000];
        ThreadLocalRandom.current().nextBytes(challenge); // Get really random bytes

        // sign using the private key
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(challenge);
        byte[] signature = sig.sign();

        // verify signature using the public key
        sig.initVerify(publicKey);
        sig.update(challenge);

        return sig.verify(signature);
    }

    /**
     * Read a PKCS 1 key in and generate the keypair from it.
     *
     * @param pem
     * @return
     * @throws Exception
     */
    public static KeyPair keyPairFromPKCS1(String pem) throws Exception {
        byte[] bytes = PEMFormatUtil.getBodyBytes(pem, BEGIN_RSA_PRIVATE_KEY, END_RSA_PRIVATE_KEY);

        DerInputStream derReader = new DerInputStream(bytes);
        DerValue[] seq = derReader.getSequence(0);
        // skip version seq[0];
        BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCoef = seq[8].getBigInteger();

        RSAPrivateCrtKeySpec keySpec =
                new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExp);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Convert the public key to PEM format using a writer.
     * @param publicKey
     * @param writer
     * @throws IOException
     */
    public static void toX509PEM(PublicKey publicKey, Writer writer) throws IOException {
        writer.write(toX509PEM(publicKey));
        writer.flush();
    }

    /**
     * Convert public key to PEM format, returning the result as a string. X509 public key is really PKCS8 public key
     * format
     * @param publicKey
     * @return
     */
    public static String toX509PEM(PublicKey publicKey) {
        byte[] bytes = publicKey.getEncoded();
        return PEMFormatUtil.delimitBody(PEMFormatUtil.bytesToChunkedString(bytes), BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
    }

    public static String toPKCS8PEM(PublicKey publicKey){
        return toX509PEM(publicKey);
    }
    public static void toPKCS8PEM(PublicKey publicKey, Writer writer) throws IOException {
        toX509PEM(publicKey, writer);
    }

    /**
     * Decode a PKCS #8 encoded private key. OpenSSL, for instance, does not put out this format
     * automatically. The standard command will generate a PEM file, e.g.,
     * <code>
     * openssl genrsa -out privkey.pem 2048
     * </code>
     * so you must convert it e.g., with the following command:<br><br>
     * <code>
     * openssl pkcs8 -topk8 -nocrypt -in privkey.pem -inform PEM -out privkey.der -outform DER
     * </code><br><br>
     * The result is that you have two copies of the private key. The one ending with extension .der
     * (which is binary) can be imported using this method. Doing this conversion in Java is well past the scope of this
     * utility. If you use this on a key in the wrong format you will get an exception.
     *
     * @param encodedPrivate
     * @return
     */
    public static PrivateKey fromPKCS8DER(byte[] encodedPrivate) {
        PKCS8EncodedKeySpec encodedPrivatePKCS8 = new PKCS8EncodedKeySpec(encodedPrivate);
        try {
            return getKeyFactory().generatePrivate(encodedPrivatePKCS8);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Convert a private key to PKCS 8 format, returning the resulting PEM as a string.
     * @param privateKey
     * @return
     */

    public static String toPKCS8PEM(PrivateKey privateKey) {
        return PEMFormatUtil.delimitBody(privateKey.getEncoded(), BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
    }

    /**
     * Convert a private key to PKCS 8 format, sending the resulting PEM to a writer.
     * @param privateKey
     * @param writer
     * @throws IOException
     */
    public static void toPKCS8PEM(PrivateKey privateKey, Writer writer) throws IOException {
        writer.write(toPKCS8PEM(privateKey));
        writer.flush();
    }

    /**
     * This takes the PEM encoding of a PKCS 8 format private key, strips the header and footer, converts
     * to bytes then invokes {@link #fromPKCS8DER(byte[])}.
     * You can get a PKCS #8 private key that is PEM encoded from open ssl e.g. with
     * <code>
     * openssl pkcs8 -topk8 -nocrypt -in privkey.pem -inform PEM -out privkey-pkcs8.pem -outform PEM
     * </code><br><br>
     *
     * @param pem
     * @return
     */
    public static PrivateKey fromPKCS8PEM(String pem) {
        return fromPKCS8DER(PEMFormatUtil.getBodyBytes(pem, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY));
    }

    /**
     * Public keys are encoded with the X509 public key spec.
     *
     * @param encodedPublic
     * @return
     */
    public static PublicKey fromX509PEM(String encodedPublic) {
        return fromX509DER(PEMFormatUtil.getBodyBytes(encodedPublic, BEGIN_PUBLIC_KEY, END_PUBLIC_KEY));
    }

    /**
     * Convert a DER encoded public key to a {@link PublicKey};
     * @param encodedPublic
     * @return
     */
    public static PublicKey fromX509DER(byte[] encodedPublic) {
        X509EncodedKeySpec x = new X509EncodedKeySpec(encodedPublic);
        try {
            return getKeyFactory().generatePublic(x);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * Gets the key length (default is 2048 bits).
     * @return
     */
    public static int getKeyLength() {
        return keyLength;
    }

    public static void setKeyLength(int length) {
        keyLength = length;
    }

    static int keyLength = 2048;

    /**
     * Create and set the keypair generator  for this suite using the current key algorithm (default is RSA).
     * @return
     */
    public static KeyPairGenerator getKeyPairGenerator() {
        if (keyPairGenerator == null) {
            try {
                keyPairGenerator = KeyPairGenerator.getInstance(getKeyAlgorithm());
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException(e);
            }
            keyPairGenerator.initialize(getKeyLength());
        }
        return keyPairGenerator;
    }


    /**
     * If you have some specific keypair generator you need to use, you can set it here,
     * @param generator
     */
    public static void setKeyPairGenerator(KeyPairGenerator generator) {
        keyPairGenerator = generator;
    }


    static KeyPairGenerator keyPairGenerator;

    /**
     * Generate a {@link KeyPair}
     * @return
     */
    public static KeyPair generateKeyPair() {
        return getKeyPairGenerator().generateKeyPair();
    }

    /**
     * Return the current key algorithm.  Default is RSA.
     * @return
     */
    public static String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public static void setKeyAlgorithm(String algorithm) {
        keyAlgorithm = algorithm;
    }

    protected static String keyAlgorithm = "RSA";
    protected static KeyFactory keyFactory;

    /**
     * Create and set key factory for this suite using the current key algorithm default is RSA.
     * @return
     */
    public static KeyFactory getKeyFactory() {
        if (keyFactory == null) {
            try {
                keyFactory = KeyFactory.getInstance(getKeyAlgorithm());
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException(e);
            }
        }
        return keyFactory;
    }

    /**
     * Create and set the key factory for this suite using the given algorithm.
     * @param keyAlgorithm
     * @return
     */
    public static KeyFactory getKeyFactory(String keyAlgorithm) {
        if (keyFactory == null) {
            try {
                keyFactory = KeyFactory.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException(e);
            }
        }
        return keyFactory;
    }
    /**
     * Ingest a PKCS 8 format PEM via a reader.
     * @param reader
     * @return
     * @throws IOException
     */
    public static PrivateKey fromPKCS8PEM(Reader reader) throws IOException {
        return fromPKCS8PEM(PEMFormatUtil.readerToString(reader));
    }

    /**
     * Ingest the public key in an X 509 PEM via a reader.
     * @param reader
     * @return
     * @throws IOException
     */
    public static PublicKey fromX509PEM(Reader reader) throws IOException {
        return fromX509PEM(PEMFormatUtil.readerToString(reader));
    }
    public static PublicKey fromPublicPKCS8PEM(Reader reader) throws IOException {
        return fromX509PEM(reader);
    }
    public static PublicKey fromPublicPKCS8PEM(String pemKey) throws IOException {
        return fromX509PEM(pemKey);
    }
    /**
     * Generate a symmetric key. Note that the length is <b>not</b> bits
     * but bytes. E.g to generate a symmetric key of 4096 bits you would call
     * <pre>
     *     byte[] sKey = generateSKey(4096/8);
     * </pre>
     * @param length
     * @return
     */
    public static byte[] generateSKey(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[length];
        secureRandom.nextBytes(key);
        return key;
    }

    public static void main(String[] args) throws Throwable{
        // Round trip tests
        //PrivateKey pKey = fromPKCS1PEM(new FileReader("/home/ncsa/dev/ncsa-git/qdl/tests/src/test/resources/crypto/pkcs1.pem"));
        PrivateKey pKey = fromPKCS1PEM(new FileReader("/tmp/pkcs1.pem"));
        toPKCS8PEM(pKey, new FileWriter("/tmp/yyy.pem"));
        pKey = fromPKCS8PEM(new FileReader("/tmp/yyy.pem"));
        System.out.println(pKey);
        PublicKey pKey1 = fromPublicPKCS1PEM(new FileReader("/home/ncsa/dev/ncsa-git/qdl/tests/src/test/resources/crypto/pkcs1_public.pem"));
        toX509PEM(pKey1, new FileWriter("/tmp/xxx.pem"));
         pKey1 = fromX509PEM(new FileReader("/tmp/xxx.pem"));
    }

}
