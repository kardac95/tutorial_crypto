package main;

import crypto.Crypto;

public class RSA {
    public static void main(String[] args) {

        String myData = "Kribbe thinks that kalle is the greatest";
        System.out.println("Original message: " + myData + "\n");

        try {
            Crypto crypt = new Crypto();
            System.out.println("Private key: " + crypt.getPrivateKey());
            System.out.println("Public key: " + crypt.getPublicKey());
            String encryptedPrivate=crypt.RSAEncrypt(crypt.getPrivateKey(), myData);
            System.out.println("Encrypted data Private: " + encryptedPrivate + "\n");

            String encryptedPublic=crypt.RSAEncrypt(crypt.getPublicKey(), myData);
            System.out.println("Encrypted data public: " + encryptedPrivate + "\n");

            String decryptedPrivePub = crypt.RSADecrypt(crypt.getPublicKey(), encryptedPrivate);
            System.out.println("Decrypted prive-pub: " + decryptedPrivePub);

            String decryptedPrivatePrivate = crypt.RSADecrypt(crypt.getPublicKey(), encryptedPrivate);
            System.out.println("Decrypted priv-priv: " + decryptedPrivatePrivate);

            String decryptedPublicPrivate = crypt.RSADecrypt(crypt.getPrivateKey(), encryptedPublic);
            System.out.println("Decrypted pub-priv: " + decryptedPublicPrivate);

            String decryptedPublicPublic = crypt.RSADecrypt(crypt.getPublicKey(), encryptedPublic);
            System.out.println("Decrypted priv-priv: " + decryptedPublicPublic);


        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
