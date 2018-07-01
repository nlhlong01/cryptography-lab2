package com.company;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;

public class AESEnc {

    public static void main(String[] args) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IOException, BadPaddingException, IllegalBlockSizeException {
        // set default parameters
        String filename = "";
        //String filename = "largefile.bin";
        //String filename = "largefile.bin.enc";
        //String filename = "zerofile.bin";
        String password = "";
        String mode = "CTR";
        String bLen = "0";
        boolean dec = false;
        boolean stat = false;

        // read input values
        for (int i = 0; i < args.length; i++) {
            if ("-filename".equals(args[i])) filename = args[++i];
            else if ("-password".equals(args[i])) password = args[++i];
            else if ("-mode".equals(args[i])) mode = args[++i];
            else if ("-blocklength".equals(args[i])) bLen = args[++i];
            else if ("-dec".equals(args[i])) dec = true;
            else if ("-stat".equals(args[i])) stat = true;
        }

        //  creates a File object from the string filename
        File file = new File(filename);

        // convert password from String to char[]
        char[] passwordArr = password.toCharArray();

        // call encryption or decryption method
        if (dec) {
            decrypt(passwordArr, file, mode, bLen);
        }
        else {
            File encfile = encrypt(passwordArr, file, mode, bLen);
            if (stat) {
                test(encfile);
            }
        }
    }

    private static File encrypt(char[] password, File file, String mode, String bLen) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IOException, BadPaddingException, IllegalBlockSizeException {
        // create a byte array salt with 64 random bytes
        byte[] salt = new byte[64];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(salt);

        // derive a 256-bit AES key
        SecretKeyFactory kf = null;
        kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

        // generate the key bits
        KeySpec specs = new PBEKeySpec(password, salt, 2048, 256);
        SecretKey pbkey = kf.generateSecret(specs);
        byte[] pbkeyBytes = pbkey.getEncoded();

        // generate a 16-byte counter or initialisation vector iv using SecureRandom
        byte[] iv = new byte[16];
        rand.nextBytes(iv);

        // create an IvParameterSpec object using iv
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        // get an instance of a Cipher object with the transformation "AES/CTR/NoPadding"
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        // construct a SecretKeySpec object using pbkeyBytes and the algorithm name "AES"
        SecretKeySpec k = new SecretKeySpec(pbkeyBytes, "AES");

        // initialize the Cipher object with the cipher mode (encryption or decryption), the SecretKeySpec object and
        //the IvParameterSpec object
        cipher.init(Cipher.ENCRYPT_MODE, k, ivspec);

        // create a FileInputStream (using the given file),
        // a CipherInputStream (using the FileInputStream and Cipher objects)
        // and a FileOutputStream
        FileInputStream infile = new FileInputStream(file);
        CipherInputStream cis = new CipherInputStream(infile, cipher);
        File encfile = new File(file.getName() + ".enc");
        FileOutputStream out = new FileOutputStream(encfile);

        // The data is written to the FileOutputStream using the write method
        out.write(salt);
        out.write(iv);

        // read encrypted blocks of data into a byte array b and write them to the output stream
        byte[] b = new byte[Integer.parseInt(bLen)];
        //byte[] infileBytes = infile.readAllBytes();
        long t0 = System.currentTimeMillis();
        int i = cis.read(b);
        while (i != -1) {
            out.write(b, 0, i);
            i = cis.read(b);
        }
        //byte[] b = cipher.doFinal(infileBytes);
        long t1 = System.currentTimeMillis();
        //out.write(b);

        // close open streams
        infile.close();
        cis.close();
        out.close();

        // print file size, encryption time, throughput
        long l = file.length();
        long t = t1 - t0;
        double thr = (l*Math.pow(10, 3))/(t*Math.pow(10, 6));
        System.out.println("-- Encryption Mode --");
        System.out.println("Size: " + file.length() + "B");
        System.out.println("Time: " + t + "ms");
        System.out.println("Throughput: " + thr + "MB/s");

        return encfile;
    }

    private static void decrypt(char[] password, File file, String mode, String bLen) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        // read the salt bytes and the initialisation vector from the FileInputStream
        FileInputStream infile = new FileInputStream(file);
        //byte[] fisByte = infile.readAllBytes();
        byte[] salt = new byte[64];
        infile.read(salt);
        byte[] iv = new byte[16];
        infile.read(iv);
        //byte[] salt = Arrays.copyOfRange(fisByte, 0, 64);
        //byte[] iv = Arrays.copyOfRange(fisByte, 64, 80);
        //byte[] encText = Arrays.copyOfRange(fisByte, 80, fisByte.length);

        // derive a 256-bit AES key
        SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

        // generate the key bits
        KeySpec specs = new PBEKeySpec(password, salt, 2048, 256);
        SecretKey pbkey = kf.generateSecret(specs);
        byte[] pbkeyBytes = pbkey.getEncoded();

        // construct a SecretKeySpec object using pbkeyBytes and the algorithm name "AES"
        SecretKeySpec k = new SecretKeySpec(pbkeyBytes, "AES");

        // create an IvParameterSpec object using iv
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        // get an instance of a Cipher object with the transformation "AES/CTR/NoPadding"
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        // initialize the Cipher object
        cipher.init(Cipher.DECRYPT_MODE, k, ivspec);

        // create a CipherInputStream and a FileOutputStream
        CipherInputStream cis = new CipherInputStream(infile, cipher);
        File decFile = new File(file.getName() + ".dec");
        FileOutputStream out = new FileOutputStream(decFile);

        // read encrypted blocks of data into a byte array b and write them to the output stream
        long t0 = System.currentTimeMillis();
        //byte[] decText = cipher.doFinal(encText);
        byte[] b = new byte[Integer.parseInt(bLen)];
        //byte[] infileBytes = infile.readAllBytes();
        int i = cis.read(b);
        while (i != -1) {
            out.write(b, 0, i);
            i = cis.read(b);
        }
        //byte[] b = cipher.doFinal(infileBytes);
        long t1 = System.currentTimeMillis();

        infile.close();
        out.close();

        // print file size, encryption time, throughput
        long l = file.length();
        long t = t1 - t0;
        double thr = (l*Math.pow(10, 3))/(t*Math.pow(10, 6));
        System.out.println("-- Decryption Mode --");
        System.out.println("Size: " + file.length() + "B");
        System.out.println("Time: " + t + "ms");
        System.out.println("Throughput: " + thr + "MB/s");
    }

    private static void test(File file) throws IOException {
        // get encrypted text from input file
        FileInputStream infile = new FileInputStream(file);
        infile.skip(80);

        // calculate parameters
        long n = file.length() - 80;
        double E = n/256;

        // print number of occurence of every byte value
        int[] N = new int[256];
        int i = infile.read();
        while (i != -1) {
            N[i]++;
            i = infile.read();
        }

        //calculate the result
        double chi_sqr = 0;
        for (int j = 0; j < 256; j++) {
            chi_sqr += Math.pow((N[j] - E), 2) / E;
        }
        System.out.println("chi^2 = " + chi_sqr);
    }
}
