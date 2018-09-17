package org.emau.icmvc.ganimed.ttp.psn.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AESKeyGenerator {

    private SecretKey secretKey;

    public AESKeyGenerator() throws NoSuchAlgorithmException {
    	KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    	keyGen.init(128, new SecureRandom());
    	setSecretKey(keyGen.generateKey());
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }
    
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        AESKeyGenerator keyGenerator = new AESKeyGenerator();
        keyGenerator.writeToFile("AES/secretKey", keyGenerator.getSecretKey().getEncoded());
        System.out.println(Base64.getEncoder().encodeToString(keyGenerator.getSecretKey().getEncoded()));
    }

	public SecretKey getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(SecretKey secretKey) {
		this.secretKey = secretKey;
	}
}
