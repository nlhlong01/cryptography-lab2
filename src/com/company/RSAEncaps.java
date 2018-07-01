package com.company;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.math.*;

public class RSAEncaps {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            IOException {
        BigInteger N = null;
        BigInteger e = new BigInteger("65537");

        for (int i = 0; i < args.length; i++) {
            if ("-modulus".equals(args[i])) N = new BigInteger(args[++i]);
        }

        // Generate a random 32-byte key k
        byte[] k = new byte[32];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(k);

        // Create a PublicKey object from the public key parameters e and N
        RSAPublicKeySpec mykeyspec = new RSAPublicKeySpec(N, e);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey mypubKey = keyFactory.generatePublic(mykeyspec);

        // Initialize a Cipher object
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, mypubKey);

        long t0 = System.currentTimeMillis();
        byte[] cipherText = cipher.doFinal(k);
        long t1 = System.currentTimeMillis();

        // Write out the plain text key and the encrypted key
        //File plainTextKeyFile = new File("key.bin");
        FileOutputStream out = new FileOutputStream("key.bin");
        out.write(k);
        out.close();
        out = new FileOutputStream("key.enc");
        out.write(cipherText);
        out.close();
        System.out.println("Encapsulation Time: " + (t1-t0) + "ms");
    }
}
