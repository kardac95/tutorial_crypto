package crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Crypto {
    public SecretKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(SecretKey privateKey) {
        this.privateKey = privateKey;
    }

    private SecretKey privateKey;
    private SecretKey publicKey;

    public void generatePrivateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        privateKey = keyGen.generateKey();
    }

    private byte[] generateInitVector(int blockSize) {
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[blockSize];
        randomSecureRandom.nextBytes(iv);
        return iv;

    }

    public String encrypt(String key, String value) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(generateInitVector(16));
        System.out.println(key.getBytes().length);
        //hashing key
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        //SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        System.out.println(value);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String key, String encrypted) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(generateInitVector(16));


        //SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        //hashing key
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);

        //SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        return new String(original);
    }


}
