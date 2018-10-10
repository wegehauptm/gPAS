package org.emau.icmvc.ganimed.ttp.psn.internal;

import java.security.Key;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

//import javax.persistence.Converter;


@Converter
public class PasswordConverter implements AttributeConverter<String, String>{
	
		private static String ALGORITHM = null;
		private static byte[] KEY = null;
		
		public static final String algorithm_property_key = "encryption.algorithm";
		public static final String secret_property_key = "encryption.key";
		
		static final Properties properties = new Properties();
		static {
			properties.put(algorithm_property_key, "AES/ECB/PKCS5Padding");
			properties.put(secret_property_key, "MySuperSecretKey");
			ALGORITHM = (String) properties.get(algorithm_property_key);
			KEY = ((String) properties.get(secret_property_key)).getBytes();
		}
	
		@Override
		public String convertToDatabaseColumn(String attribute) {		  
			Key key = new SecretKeySpec(KEY, "AES");
			try {
				final Cipher c = Cipher.getInstance(ALGORITHM);
				c.init(Cipher.ENCRYPT_MODE, key);
				final String encrypted = new String(Base64.getEncoder().encodeToString(c.doFinal(attribute.getBytes())));
				//UTF 8 is missing. Original code: final String encrypted = new String(Base64.encode(c.doFinal(sensitive.getBytes())), "UTF-8");
				return encrypted;
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		
		@Override
		public String convertToEntityAttribute(String dbData) {
			Key key = new SecretKeySpec(KEY, "AES");
			try {
				final Cipher c = Cipher.getInstance(ALGORITHM);
				c.init(Cipher.DECRYPT_MODE, key);
				final String decrypted = new String(c.doFinal(Base64
						.getDecoder().decode(dbData.getBytes("UTF-8"))));
				return decrypted;
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
	}