package org.emau.icmvc.ganimed.ttp.psn.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AESUtil {

    public static String secretKey = "nSCyKNUinUjkOqEf";

    public static SecretKeySpec getSecretKey(String base64SecretKey){
    	SecretKeySpec skeySpec=null;
        try{
            skeySpec = new SecretKeySpec(base64SecretKey.getBytes("UTF-8"), "AES");
            //skeySpec = new SecretKeySpec(DatatypeConverter.parseHexBinary(base64SecretKey), "AES");
            return skeySpec;
        } catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return skeySpec;
    }

    public static byte[] encrypt(String data, String secretKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(secretKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String decrypt(String dataStr, String secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    	byte[] data=Base64.getDecoder().decode(dataStr.getBytes());
    	Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(secretKey));
        return new String(cipher.doFinal(data));
    }

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        try {
            String encryptedString = Base64.getEncoder().encodeToString(encrypt("123456789", secretKey));
            System.out.println(encryptedString);
            String decryptedString = AESUtil.decrypt(encryptedString, secretKey);
            System.out.println(decryptedString);
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }
    }
}