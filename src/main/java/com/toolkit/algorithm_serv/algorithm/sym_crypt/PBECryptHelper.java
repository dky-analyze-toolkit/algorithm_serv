package com.toolkit.algorithm_serv.algorithm.sym_crypt;

import cn.hutool.core.util.HexUtil;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public class PBECryptHelper {
    private static final int RANDOM_SIZE = 32;
    private static final int ITERATION_COUN = 100;
    // private static final Map<String, Integer>

    public static byte[] initSalt() {
        SecureRandom random = new SecureRandom();
        return random.generateSeed(RANDOM_SIZE);
    }

    public static String initSaltHex() {
        byte[] salt = initSalt();
        return HexUtil.encodeHexStr(salt, false);
    }

    public static Key pwdToKey(String alg, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 基于密码生成PBE密钥参数对象
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        // 实例化密钥工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(alg);
        // 生成密钥
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        return secretKey;
    }

    public static byte[] encrypt(String alg, byte[] plain, String password, byte[] salt) throws Exception {
        // 从密码转换密钥
        Key key = pwdToKey(alg, password);
        // 实例化PBE参数
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUN);
        // 实例化算法对象
        Cipher cipher = Cipher.getInstance(alg);
        // 对算法对象做加密初始化
        cipher.init(cipher.ENCRYPT_MODE, key, paramSpec);

        // 加密
        return cipher.doFinal(plain);
    }

    public static String encrypt(String alg, String plainHex, String password, String saltHex) throws Exception {
        byte[] plain = HexUtil.decodeHex(plainHex);
        byte[] salt = HexUtil.decodeHex(saltHex);

        byte[] result = encrypt(alg, plain, password, salt);
        return HexUtil.encodeHexStr(result, false);
    }

    public static byte[] decrypt(String alg, byte[] cipherData, String password, byte[] salt) throws Exception {
        // 从密码转换密钥
        Key key = pwdToKey(alg, password);
        // 实例化PBE参数
        PBEParameterSpec paramSpec = new PBEParameterSpec(salt, ITERATION_COUN);
        // 实例化算法对象
        Cipher cipher = Cipher.getInstance(alg);
        // 对算法对象做解密初始化
        cipher.init(cipher.DECRYPT_MODE, key, paramSpec);

        // 解密
        return cipher.doFinal(cipherData);
    }

    public static String decrypt(String alg, String cipherHex, String password, String saltHex) throws Exception {
        byte[] cipherData = HexUtil.decodeHex(cipherHex);
        byte[] salt = HexUtil.decodeHex(saltHex);

        byte[] result = decrypt(alg, cipherData, password, salt);
        return HexUtil.encodeHexStr(result, false);
    }
}
