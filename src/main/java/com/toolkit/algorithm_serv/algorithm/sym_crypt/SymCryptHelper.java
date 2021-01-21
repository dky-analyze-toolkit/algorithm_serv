package com.toolkit.algorithm_serv.algorithm.sym_crypt;

import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.symmetric.*;
import com.toolkit.algorithm_serv.algorithm.hash.HashHelper;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;

import java.io.UnsupportedEncodingException;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class SymCryptHelper {
    // private static final Map<String, Boolean> validKeySizeMap = new HashMap<>(5);
    // static {
    //     validKeySizeMap.put("DES", Boolean.TRUE);
    // }
    // private static final List<String> algLists = Lists.newArrayList("AES", "DES", "DESede");


    public static byte[] generateKey(String alg, int keySize) throws IllegalArgumentException {
        ParamsHelper.checkAlgKeySize(alg, keySize);

        // 随机生成密钥
        byte[] key = KeyUtil.generateKey(alg, keySize).getEncoded();
        return key;
    }

    public static String generateKeyHex(String alg, int keyLen) {
        return StrAuxUtils.bytesToHexString(SymCryptHelper.generateKey(alg, keyLen));
    }

    private static SymmetricCrypto initCrypto(String alg, Mode mode, Padding padding, byte[] key, byte[] iv) {
        if (mode == Mode.ECB) {
            iv = null;
        } else {
            iv = ParamsHelper.checkIV(alg, iv);
        }

        if (alg.equals("DES")) {
            return new DES(mode, padding, key, iv);
        } else if (alg.equals("AES")) {
            return new AES(mode, padding, key, iv);
        } else if (alg.equals("DESede")) {
            return new DESede(mode, padding, key, iv);
        } else if (alg.equals("SM4")) {
            return new SM4(mode, padding, key, iv);
        }

        return null;
    }

    public static byte[] encrypt(String alg, String modeName, String paddingName, byte[] plain, byte[] key, byte[] iv)
            throws InvalidKeyException {
        ParamsHelper.checkKeySize(alg, key.length * 8);
        ParamsHelper.checkModePadding(modeName, paddingName);

        Mode mode = ParamsHelper.getMode(modeName);
        Padding padding = ParamsHelper.getPadding(paddingName);
        SymmetricCrypto crypto = initCrypto(alg, mode, padding, key, iv);

        // JCEUtil.removeCryptographyRestrictions();
        return crypto.encrypt(plain);
    }

    public static String encrypt(String alg, String modeName, String paddingName, String plainHex, String keyHex, String ivHex)
            throws InvalidKeyException {
        byte[] plain = StrAuxUtils.hexStringToBytes(plainHex);
        byte[] key = StrAuxUtils.hexStringToBytes(keyHex);
        byte[] iv = StrAuxUtils.hexStringToBytes(ivHex);

        byte[] cipher = encrypt(alg, modeName, paddingName, plain, key, iv);

        return StrAuxUtils.bytesToHexString(cipher);
    }

    public static byte[] decrypt(String alg, String modeName, String paddingName, byte[] cipher, byte[] key, byte[] iv)
            throws InvalidKeyException {
        ParamsHelper.checkKeySize(alg, key.length * 8);
        ParamsHelper.checkModePadding(modeName, paddingName);

        SymmetricCrypto crypto = initCrypto(alg, ParamsHelper.getMode(modeName), ParamsHelper.getPadding(paddingName), key, iv);

        // JCEUtil.removeCryptographyRestrictions();
        return crypto.decrypt(cipher);
    }

    public static String decrypt(String alg, String modeName, String paddingName, String cipherHex, String keyHex, String ivHex)
            throws InvalidKeyException {
        byte[] cipher = StrAuxUtils.hexStringToBytes(cipherHex);
        byte[] key = StrAuxUtils.hexStringToBytes(keyHex);
        byte[] iv = StrAuxUtils.hexStringToBytes(ivHex);

        byte[] plain = decrypt(alg, modeName, paddingName, cipher, key, iv);

        return StrAuxUtils.bytesToHexString(plain);
    }

}
