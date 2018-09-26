package main;

import crypto.Crypto;

public class AES {
    public static void main(String[] args) {

        String myData = "kalle is the greatest";
        System.out.println("Original message: " + myData + "\n");

        try {
            Crypto crypt = new Crypto();
            String encryptedData=crypt.AESEncrypt(crypt.getSkey().toString(), myData);
            System.out.println("Encrypted data: " + encryptedData + "\n");

            String decryptedData = crypt.AESDecrypt(crypt.getSkey().toString(), encryptedData);
            System.out.println("Decrypted data: " + decryptedData);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
