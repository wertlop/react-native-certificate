package com.reactnativecertificate;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES256Util {
    private byte[] iv;
    private byte[] keyBytes;
    private Key keySpec;
    public AES256Util(String key) throws UnsupportedEncodingException {
        this.iv = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        this.keyBytes = new byte[16];
        byte[] b = key.getBytes();
        int len = b.length;
        if (len > keyBytes.length) {
            len = keyBytes.length;
        }
        System.arraycopy(b, 0, keyBytes, 0, len);
        SecretKeySpec keySpec = new SecretKeySpec(this.keyBytes, "AES");
        this.keySpec = keySpec;
    }

    public byte[] getKeyBytes() {
        return this.keyBytes;
    }

    // 암호화
    public String encodeBytes(byte[] b) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
      Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
      c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
      byte[] encrypted = c.doFinal(b);
      return Base64.encodeToString(encrypted, 0);
    }
    // 암호화
    public String encode(String str) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
        c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] encrypted = c.doFinal(str.getBytes());
        return Base64.encodeToString(encrypted, 0);
    }

    //복호화
    public String decode(String str) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
        c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] byteStr = Base64.decode(str.getBytes(), 0);
        return new String(c.doFinal(byteStr));
    }
}
