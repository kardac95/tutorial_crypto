package crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class Crypto {
    public SecretKey getSkey() {
        return skey;
    }

    private SecretKey skey;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private IvParameterSpec iv;

    public Crypto() throws NoSuchAlgorithmException {
        iv = new IvParameterSpec(generateInitVector(16));
        generateSkey();
        generateRSAKeyPair(2048);
    }

    private void generateRSAKeyPair(int keyLength) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keyLength);
        KeyPair p = kpg.generateKeyPair();
        this.privateKey = p.getPrivate();
        this.publicKey = p.getPublic();
    }

    private void generateSkey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        this.skey = keyGen.generateKey();
    }

    private byte[] generateInitVector(int blockSize) {
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[blockSize];
        randomSecureRandom.nextBytes(iv);
        return iv;

    }

    public byte[] hashKey(String key) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        return keyBytes;
    }

    public String AESEncrypt(String key, String value) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(hashKey(key), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String AESDecrypt(String key, String encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(hashKey(key), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        return new String(original);
    }


    public String RSAEncrypt(Key key, String value) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes("UTF-8")));
    }

    public String RSADecrypt(Key key, String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)), "UTF-8");
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
