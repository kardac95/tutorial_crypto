package main;

import crypto.Crypto;
import jdk.internal.cmm.SystemResourcePressureImpl;

public class AES {
    public static void main(String[] args) {
        Crypto crypt = new Crypto();

        String myData = "aaaaaaaaaaaaaaaakallekallekalle";
        System.out.println(myData);

        try {
            crypt.generatePrivateKey();
            System.out.println(crypt.getPrivateKey());
            System.out.println();
            String encryptedData=crypt.encrypt(crypt.getPrivateKey().toString(), myData);
            System.out.println(encryptedData);
            System.out.println();
            System.out.println(crypt.getPrivateKey());
            String decryptedData = crypt.decrypt(crypt.getPrivateKey().toString(), encryptedData);
            System.out.println(decryptedData);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
