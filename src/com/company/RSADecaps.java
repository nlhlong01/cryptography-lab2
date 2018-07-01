package com.company;

import java.io.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.math.*;

public class RSADecaps {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            IOException {
        BigInteger N = null;
        String filename = "key.enc";
        BigInteger d = null;

        for (int i = 0; i < args.length; i++) {
            if ("-modulus".equals(args[i])) N = new BigInteger(args[++i]);
            else if ("-privexp".equals(args[i])) d = new BigInteger(args[++i]);
            else if ("-filename".equals(args[i])) filename = args[++i];
        }

        // Create a PrivateKey object
        RSAPrivateKeySpec mykeyspec = new RSAPrivateKeySpec(N, d);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey mypriKey = keyFactory.generatePrivate(mykeyspec);

        // Initialize a Cipher object
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, mypriKey);

        // Decrypt
        File cipherTextFile = new File("key.enc");
        byte[] cipherTextByte = new byte[(int) cipherTextFile.length()];
        FileInputStream in = new FileInputStream(cipherTextFile);
        in.read(cipherTextByte);
        in.close();

        long t0 = System.currentTimeMillis();
        byte[] plainText = cipher.doFinal(cipherTextByte);
        long t1 = System.currentTimeMillis();

        // Write out the decapsulated key
        FileOutputStream out = new FileOutputStream(filename + ".dec");
        out.write(plainText);
        out.close();
        System.out.println("Decapsulation Time: " + (t1-t0) + "ms");
    }

}
