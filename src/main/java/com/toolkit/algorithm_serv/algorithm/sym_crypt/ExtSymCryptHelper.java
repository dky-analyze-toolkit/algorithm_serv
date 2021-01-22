package com.toolkit.algorithm_serv.algorithm.sym_crypt;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.CryptoException;
import cn.hutool.crypto.symmetric.RC4;
import cn.hutool.crypto.symmetric.Vigenere;
import com.google.common.base.Preconditions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExtSymCryptHelper {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    public static byte[] rc4Encrypt(byte[] plain, String key) {
        Preconditions.checkArgument(plain != null && plain.length > 0, "没有输入明文数据");
        RC4 rc4 = new RC4(key);
        return rc4.crypt(plain);
    }

    public static String rc4EncryptHex(String plainHex, String key) {
        byte[] cipher = rc4Encrypt(HexUtil.decodeHex(plainHex), key) ;
        return HexUtil.encodeHexStr(cipher, false);
    }

    public static byte[] rc4Decrypt(byte[] cipher, String key) {
        Preconditions.checkArgument(cipher != null && cipher.length > 0, "没有输入密文数据");
        RC4 rc4 = new RC4(key);
        return rc4.crypt(cipher);
    }

    public static String rc4DecryptHex(String cipherHex, String key) {
        byte[] plain = rc4Decrypt(HexUtil.decodeHex(cipherHex), key) ;
        return HexUtil.encodeHexStr(plain, false);
    }

    public static String vigenereEncrypt(String plain, String key) {
        Preconditions.checkArgument(plain != null && plain.length() > 0, "没有输入明文数据");
        return Vigenere.encrypt(plain, key);
    }

    public static String vigenereDecrypt(String cipher, String key) {
        Preconditions.checkArgument(cipher != null && cipher.length() > 0, "没有输入密文数据");
        return Vigenere.decrypt(cipher, key);
    }

    public static String encrypt(String alg, String plain, String key) {
        if (alg.equals("RC4")) {
            return rc4EncryptHex(plain, key);
        } else if (alg.equals("Vigenere")) {
            return vigenereEncrypt(plain, key);
        } else {
            throw new CryptoException("不支持【%s】算法", alg);
        }
    }

    public static String decrypt(String alg, String cipher, String key) {
        if (alg.equals("RC4")) {
            return rc4DecryptHex(cipher, key);
        } else if (alg.equals("Vigenere")) {
            return vigenereDecrypt(cipher, key);
        } else {
            throw new CryptoException("不支持【%s】算法", alg);
        }
    }
}
