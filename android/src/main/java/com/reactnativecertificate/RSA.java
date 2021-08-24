package com.reactnativecertificate;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class RSA {
    PublicKey publicKey;
    PrivateKey privateKey;
    RSAPublicKey pub;
    RSAPrivateKey pvt;

    public static String ByteArrayToHexString(byte[] ba) {
        if (ba == null || ba.length == 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (final byte b : ba) {
            sb.append(String.format("%02X", b & 0xff));
        }

        return sb.toString().substring(0, sb.toString().length()).toUpperCase();
    }

    /*
    RSA 생성
    * */
    public void generatorKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        pub = (RSAPublicKey)keyPair.getPublic();
        pvt = (RSAPrivateKey)keyPair.getPrivate();

        System.out.println(pub);
        System.out.println(pvt);

        BigInteger biModulus = pub.getModulus();
        BigInteger biExponent = pub.getPublicExponent();

        BigInteger biPrivateExponent = pvt.getPrivateExponent();

        byte [] bModulus = biModulus.toByteArray();
        String strModulus = ByteArrayToHexString(bModulus);

        byte [] bExponent = biExponent.toByteArray();
        String strExponent = ByteArrayToHexString(bExponent);

        byte [] bPrivateExponent = biPrivateExponent.toByteArray();
        String strPrivateExponent = ByteArrayToHexString(bPrivateExponent);


        System.out.printf("Modulus: [%s]\n", strModulus);
        System.out.printf("Exponent: [%s]\n", strExponent);
        System.out.printf("Private Exponent: [%s]\n", strPrivateExponent);

        BigInteger modulus = new BigInteger(strModulus, 16);
        BigInteger exponent = new BigInteger(strExponent, 16);
        BigInteger privateExponent = new BigInteger(strPrivateExponent, 16);


        this.publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus,exponent));
        this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus,privateExponent));

        System.out.println(this.publicKey);
        System.out.println(this.privateKey);

    }

    /*
    public key로 암호화
    * */
    public byte[] encryptRSA(String plainText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, IOException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

//        byte[] bPublicKey = Base64.decode(this.publicKey.getEncoded(),Base64.DEFAULT);
//        RSAPrivateCrtKeySpec keySpec =  PKCS1Util.decodePKCS1(bPublicKey);
//        Key key = keyFactory.generatePublic(keySpec);


        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);

        // 평문을 암호화하는 과정
        byte[] bytePlain = cipher.doFinal(plainText.getBytes());

        return bytePlain;
    }


    /*
    private key로 복호화
    * */
    public byte[] decryptRSA(byte[] encryptMsg)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, IOException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

//        byte[] bPrivateKey = Base64.decode(this.privateKey.getEncoded(),Base64.DEFAULT);
//        RSAPrivateCrtKeySpec keySpec =  PKCS1Util.decodePKCS1(bPrivateKey);
//        Key key = keyFactory.generatePrivate(keySpec);

        cipher.init(Cipher.DECRYPT_MODE, this.pvt);
        byte[] bytePlain = cipher.doFinal(encryptMsg);

        return bytePlain;
    }

}
