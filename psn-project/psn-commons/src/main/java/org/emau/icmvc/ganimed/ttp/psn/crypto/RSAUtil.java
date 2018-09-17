package org.emau.icmvc.ganimed.ttp.psn.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {

    public static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5vK2pT+OYYlI34DKzAk+lAoySClGfhN1q8OWFYOOapgPA/D18DlI3xTdSsKWTkNDnPWGtJlfY4cQPZfCNuF9cnkRMLR4u4ukx945+6OmxSQpSE+0dH5J44zlT7dWTwtVqCCQWYmJ6WfX3NZOnjFMep05NCeG2XQ1YfxMSTAxNzwIDAQAB";
    private static String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALm8ralP45hiUjfgMrMCT6UCjJIKUZ+E3Wrw5YVg45qmA8D8PXwOUjfFN1KwpZOQ0Oc9Ya0mV9jhxA9l8I24X1yeREwtHi7i6TH3jn7o6bFJClIT7R0fknjjOVPt1ZPC1WoIJBZiYnpZ9fc1k6eMUx6nTk0J4bZdDVh/ExJMDE3PAgMBAAECgYEAsqHKC4pwBACbvm17lTplyvd2poYSFm88XDuvIuYaQIPmHFb78zH61PRxzq9hr1iZ8avRIyw7VLVdUMnj3wkxfEgANk3STUxK1AEcQXnPKgDQ9obil2voNaRtw0eGyDATqip2sm/A2HRBbn+u+o59zFcJmMHYVUgGcUATpqJ5BFECQQDnASW90JXI2rBJ/cPmEnIgC8vZOkB82j9bnQmaWuxWVdiBUAF68o6RN/8D/kBBGeOZBrZ7HF4hbNzT+bN61lCLAkEAzdWd5rwd2v8UXY9KU7QuE8n6gyb/LmPV45U1SkRqyAF9FIyHk4UrljVoozAAbMMwuEOkICVWzUJdDNttwVC8TQJAKRTcKGia6rBxn4cAur7XCvnuE8C3TTzm/Zzs40V+OFBmA4E98iaG0i6aLJSfyrQW9NTryPMfjmQ01YHXuGW6xwJAfQUouUK9Z4zTU9h6rsibzA08CXkgOY8OFQNFsOxJZ13wGREaL/IM/VlHSwcW2vjbmLAM+jFzvYx3dB27VlWxaQJAbI/iJV29iKGA0ym6cHwj/kfjgty78vJ+/izHY0StSUqL+sG9TEK6yILCbr4jPW2/RFtEFYqekC/K/QANAAp3lQ==";

    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
    }

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        try {
            String encryptedString = Base64.getEncoder().encodeToString(encrypt("123456789", publicKey));
            System.out.println(encryptedString);
            String decryptedString = RSAUtil.decrypt("q8V0s2XbWi4nrv+apLWzSFeAgbAmJvxslDnUGODS88hLpgiGLHxP5s7tZ6dc8WDFuDpy/STx9C+ydkgIzhPQ+zXXGrMoKVrdqXHy34v7tVEUSuUCiQWqGR4eKgxXlBe0uuPhPFdOJYl0kv8UIbzlQ6CGy0W/06QCByZvG5yhC3M=", privateKey);
            System.out.println(decryptedString);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }
    }
}