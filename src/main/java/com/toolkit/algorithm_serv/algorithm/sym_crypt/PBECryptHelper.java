package com.toolkit.algorithm_serv.algorithm.sym_crypt;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public class PBECryptHelper {
    private static final int RANDOM_SIZE = 32;
    private static final int ITERATION_COUN = 100;
    private static final Map<String, Integer> algSaltLenMap = ImmutableMap.<String, Integer>builder()
            .put("PBEWithMD5AndDES", 8)
            .put("PBEWithSHA1AndDESede", 8)
            .put("PBEWithSHA1AndRC2_40", 8)
            .build();

    public static void checkAlg(String alg) {
        Preconditions.checkArgument(!Strings.isNullOrEmpty(alg), "未指定算法");
        Preconditions.checkArgument(algSaltLenMap.containsKey(alg), "不能识别【%s】算法", alg);
    }

    public static void checkSaltSize(String alg, int saltSize) {
        Preconditions.checkArgument(saltSize >= algSaltLenMap.get(alg), "【%s】算法的盐长度至少为【%s】位",
                alg, algSaltLenMap.get(alg));
    }

    public static void checkAlgSaltSize(String alg, int saltSize) {
        checkAlg(alg);
        checkSaltSize(alg, saltSize);
    }

    public static byte[] initSalt(String alg, int saltSize) {
        checkAlgSaltSize(alg, saltSize);
        SecureRandom random = new SecureRandom();
        return random.generateSeed(saltSize);
    }

    public static String initSaltHex(String alg, int saltSize) {
        byte[] salt = initSalt(alg, saltSize);
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

    public static byte[] encrypt(String alg, byte[] plain, String password, byte[] salt)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        checkAlgSaltSize(alg, salt.length);

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

    public static String encrypt(String alg, String plainHex, String password, String saltHex)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        byte[] plain = HexUtil.decodeHex(plainHex);
        byte[] salt = HexUtil.decodeHex(saltHex);

        byte[] result = encrypt(alg, plain, password, salt);
        return HexUtil.encodeHexStr(result, false);
    }

    public static byte[] decrypt(String alg, byte[] cipherData, String password, byte[] salt) throws Exception {
        checkAlgSaltSize(alg, salt.length);

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
