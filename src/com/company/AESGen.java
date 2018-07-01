package com.company;

import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.math.*;

public class AESGen {

    public static void main(String[] args) {
        int bitlength = 1024;

        for (int i = 0; i < args.length; i++) {
            if ("-length".equals(args[i])) bitlength = Integer.parseInt(args[++i]);
        }

        SecureRandom rand = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitlength, rand);
        BigInteger q = BigInteger.probablePrime(bitlength, rand);
        BigInteger N = p.multiply(q);
        BigInteger e = new BigInteger("65537");
        BigInteger phiN = p.subtract(BigInteger.valueOf(1)).multiply(q.subtract(BigInteger.valueOf(1)));
        BigInteger d = e.modInverse(phiN);
        System.out.println("p = " + p.toString());
        System.out.println("q = " + q.toString());
        System.out.println("N = " + N.toString());
        System.out.println("d = " + d.toString());
    }
}
