package edu.uiuc.ncsa.security.util.crypto;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.plaf.IconUIResource;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * A set of utilities to encrypt or decrypt a string using public/private keys.
 * <p>Created by Jeff Gaynor<br>
 * on 8/15/22 at  12:33 PM
 */

public class DecryptUtils {
    /**
     * Tests this in a chatty way if you want to run it. No arguments needed.
     *
     * @param args
     * @throws Throwable
     */
    public static void main(String[] args) throws Throwable {
        System.out.println(listCiphers());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        String target = "mairzy doats\n and dozey doats";

        String privateEncrypted = encryptPrivate(keyPair.getPrivate(), target);

        System.out.println(privateEncrypted);
        System.out.println(decryptPublic(keyPair.getPublic(), privateEncrypted));
        String publicEncrypted = encryptPublic(keyPair.getPublic(), target + ":\n public");
        System.out.println("public encryted=" + publicEncrypted);
        System.out.println(decryptPrivate(keyPair.getPrivate(), publicEncrypted));

        byte[] sKey = KeyUtil.generateSKey(16); // 16 bytes = 128 bits
        /*
        We use only 128 bits here because the encryption requires multiple loops through the key
        This tests (the quite usual case) that the string is much longer than the key
         */
        String sEncrypted = sEncrypt(sKey, LOREM);

        System.out.println("skey test encrypted:" + sEncrypted);

        String sDecrypt = sDecrypt(sKey, sEncrypted);
        System.out.println("skey test decrypted:" + sDecrypt);
        System.out.println("Equals original string? " + LOREM.equals(sDecrypt));
    }

    public static String LOREM = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt " +
            "ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut " +
            "aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore " +
            "eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt " +
            "mollit anim id est laborum.";

    /**
     * Takes a  public key and a string, then encrypts the string, converts resulting bytes to base 64 encoded ur-safe string
     *
     * @param publicKey
     * @param s
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String encryptPublic(PublicKey publicKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        return encryptPublic("RSA", publicKey, s);
    }

    public static String encryptPublic(String type, PublicKey publicKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance(type.equals("RSA") ? "RSA" : "AES/GCM/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey); // encrypt with the public key
        byte[] encryptedMessageBytes = encryptCipher.doFinal(s.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.encodeBase64URLSafeString(encryptedMessageBytes);
        return encoded;
    }

    /**
     * Decrypts a base64 encoded byte stream that encoded with the private key.
     *
     * @param publicKey
     * @param s
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String decryptPublic(PublicKey publicKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        return decryptPublic("RSA", publicKey, s);
    }

    public static String decryptPublic(String type, PublicKey publicKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        byte[] rawBytes = Base64.decodeBase64(s);
        Cipher decryptCipher = Cipher.getInstance(type);
        decryptCipher.init(Cipher.DECRYPT_MODE, publicKey); // encrypt with the public key
        byte[] decryptedMessageBytes = decryptCipher.doFinal(rawBytes);
        return new String(decryptedMessageBytes, "UTF-8");
    }


    /**
     * Encrypts a string with a private key then base 64 encodes the resulting byte stream
     *
     * @param privateKey
     * @param s
     * @return
     */
    public static String encryptPrivate(PrivateKey privateKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        return encryptPrivate("RSA", privateKey, s);
    }

    public static String encryptPrivate(String type, PrivateKey privateKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance(type);
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey); // encrypt with the public key
        byte[] encryptedMessageBytes = encryptCipher.doFinal(s.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.encodeBase64URLSafeString(encryptedMessageBytes);
        return encoded;

    }


    /**
     * <pre>
     *     orig string -> encrypt -> base64 string
     * </pre>
     *
     * @param privateKey
     * @param s
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     */
    public static String decryptPrivate(String type, PrivateKey privateKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher decryptCipher = Cipher.getInstance(type);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey); // encrypt with the public key
        byte[] rawBytes = Base64.decodeBase64(s);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(rawBytes);
        return new String(decryptedMessageBytes, "UTF-8");
    }

    public static String decryptPrivate(PrivateKey privateKey, String s) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        return decryptPrivate("RSA", privateKey, s);
    }


    /**
     * Symmetric key encryption.
     *
     * @param key
     * @param ss  The target string as bytes
     * @return
     */
    public static byte[] rawEncrypt(byte[] key, byte[] ss) {
        //byte[] ss = s.getBytes(StandardCharsets.UTF_8);
        int len = Math.max(key.length, ss.length);
        byte[] out = new byte[ss.length];
        for (int i = 0; i < ss.length; i++) {
            out[i] = (byte) (ss[i] ^ key[i % key.length]); // bit-wise XOR
        }
        return out;
    }


    /**
     * Takes a string and encrypts it with the given symmetric key.
     * Returns the base 64 encoded byte string.
     * <pre>
     *     s.equals(sEncrypt64(key, sEncrypt64(key, s))); //always is the contract
     * </pre>
     *
     * @param key
     * @param originalString
     * @return
     */
    public static String sEncrypt(byte[] key, String originalString) {
        return Base64.encodeBase64URLSafeString(rawEncrypt(key, originalString.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Takes the base 64 encrypted byte string and decrypts it, returning the original string.
     *
     * @param key
     * @param s64
     * @return
     */
    public static String sDecrypt(byte[] key, String s64) {
        try {
            return new String(rawEncrypt(key, Base64.decodeBase64(s64.getBytes(StandardCharsets.UTF_8))), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Java no longer supports UTF 8...");
        }

    }

    public static List<String> listCiphers() {
        Set<String> algs = new TreeSet<>();
        for (Provider provider : Security.getProviders()) {
            provider.getServices().stream()
                    .filter(s -> "Cipher".equals(s.getType()))
                    .map(Provider.Service::getAlgorithm)
                    .forEach(algs::add);
        }
        List<String> ciphers = new ArrayList<>(algs);
        return ciphers;
    }
}
