package com.toolkit.algorithm_serv.algorithm.rsa;

import cn.hutool.core.codec.Base64Encoder;
import cn.hutool.core.convert.Convert;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.NumberUtil;
import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.PemUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.Sign;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.toolkit.algorithm_serv.utils_ex.Util;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;

import java.io.*;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.util.Map;

public class RSAHelper {
    private static final Map<String, SignAlgorithm> rsaSignAlgsMap = ImmutableMap.<String, SignAlgorithm>builder()
            .put("None", SignAlgorithm.NONEwithRSA)
            .put("MD2", SignAlgorithm.MD2withRSA)
            .put("MD5", SignAlgorithm.MD5withRSA)
            .put("SHA1", SignAlgorithm.SHA1withRSA)
            .put("SHA256", SignAlgorithm.SHA256withRSA)
            .put("SHA384", SignAlgorithm.SHA384withRSA)
            .put("SHA512", SignAlgorithm.SHA512withRSA)
            .build();

    private static final Map<String, String> rsaEncryptPadMap = ImmutableMap.<String, String>builder()
            .put("None", "RSA/None/NoPadding")
            .put("Zero", "RSA/ECB/NoPadding")
            .put("PKCS1", "RSA/ECB/PKCS1Padding")
            .build();

    public static String toPem(String type, byte[] content) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PemUtil.writePemObject(type, content, outputStream);
        return outputStream.toString();
    }

    public static String toPem(String type, String hex) {
        byte[] content = HexUtil.decodeHex(hex);
        return toPem(type, content);
    }

    public static JSONObject generateKeyPairJson(int keyBits, int rsa_e) throws IOException {
        KeyPair keyPair = KeyUtil.generateKeyPair("RSA", keyBits);
        BCRSAPrivateCrtKey privateKey = (BCRSAPrivateCrtKey)keyPair.getPrivate();
        BCRSAPublicKey publicKey = (BCRSAPublicKey)keyPair.getPublic();

        JSONObject jsonKey = new JSONObject();
        jsonKey.put("public_key_format", publicKey.getFormat());
        jsonKey.put("private_key_format", privateKey.getFormat());
        jsonKey.put("public_key_b64", publicKey.getEncoded());
        jsonKey.put("private_key_b64", privateKey.getEncoded());
        jsonKey.put("public_key_pem", toPem("PUBLIC KEY", publicKey.getEncoded()));
        jsonKey.put("private_key_pem", toPem("PRIVATE KEY", privateKey.getEncoded()));
        String rsaN = privateKey.getModulus().toString(16);
        jsonKey.put("rsa_n", rsaN);
        jsonKey.put("rsa_d", privateKey.getPrivateExponent().toString(16));
        jsonKey.put("rsa_e", privateKey.getPublicExponent().toString(16));
        jsonKey.put("rsa_p", privateKey.getPrimeP().toString(16));
        jsonKey.put("rsa_q", privateKey.getPrimeQ().toString(16));
        jsonKey.put("modulus_bits", rsaN.length() * 4);
        jsonKey.put("modulus_size", rsaN.length() / 2);

        return jsonKey;
    }

    public static JSONObject readPem(String pem) {
        JSONObject jsonKey = new JSONObject();
        String rsaN;
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pem.getBytes());
        Key key = PemUtil.readPemKey(inputStream);
        if (key instanceof BCRSAPublicKey) {
            BCRSAPublicKey publicKey = (BCRSAPublicKey)key;
            jsonKey.put("public_key_format", publicKey.getFormat());
            jsonKey.put("public_key_b64", publicKey.getEncoded());
            rsaN = publicKey.getModulus().toString(16);
            jsonKey.put("rsa_e", publicKey.getPublicExponent().toString(16));
        } else if (key instanceof BCRSAPrivateCrtKey) {
            BCRSAPrivateCrtKey privateKey = (BCRSAPrivateCrtKey)key;
            jsonKey.put("private_key_format", privateKey.getFormat());
            jsonKey.put("private_key_b64", privateKey.getEncoded());
            rsaN = privateKey.getModulus().toString(16);
            jsonKey.put("rsa_d", privateKey.getPrivateExponent().toString(16));
        } else {
            return null;
        }

        jsonKey.put("rsa_n", rsaN);
        jsonKey.put("modulus_bits", rsaN.length() * 4);
        jsonKey.put("modulus_size", rsaN.length() / 2);
        return jsonKey;
    }

    public static byte[] readPrivKeyFromPem(String pem) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pem.getBytes());
        BCRSAPrivateCrtKey privateKey = (BCRSAPrivateCrtKey)PemUtil.readPemPrivateKey(inputStream);
        return privateKey.getEncoded();
    }

    public static byte[] readPubKeyFromPem(String pem) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pem.getBytes());
        BCRSAPublicKey publicKey = (BCRSAPublicKey)PemUtil.readPemPublicKey(inputStream);
        return publicKey.getEncoded();
    }

    public static SignAlgorithm getRsaSignAlg(String algName) {
        Preconditions.checkArgument(rsaSignAlgsMap.containsKey(algName), "不支持签名算法：【%s】", algName);
        return rsaSignAlgsMap.get(algName);
    }

    public static String getRsaEncryptPadding(String paddingName) {
        Preconditions.checkArgument(rsaEncryptPadMap.containsKey(paddingName), "不支持加密补齐模式：【%s】", paddingName);
        return rsaEncryptPadMap.get(paddingName);
    }

    public static String sign(String signAlg, String privKeyPem, String dataHex) {

        byte[] privKey = readPrivKeyFromPem(privKeyPem);
        Sign sign = SecureUtil.sign(getRsaSignAlg(signAlg), privKey, null);

        byte[] signedResult = sign.sign(HexUtil.decodeHex(dataHex));
        return HexUtil.encodeHexStr(signedResult, false);
    }

    public static boolean verify(String signAlg, String pubKeyPem, String dataHex, String signHex) {

        byte[] pubKey = readPubKeyFromPem(pubKeyPem);
        Sign sign = SecureUtil.sign(getRsaSignAlg(signAlg), null, pubKey);

        return sign.verify(HexUtil.decodeHex(dataHex), HexUtil.decodeHex(signHex));
    }

    public static byte[] modularExp(byte[] data, byte[] modulus, byte[] exp) {
        BigInteger biData = Convert.toBigInteger(data);
        BigInteger biModulus = Convert.toBigInteger(modulus);
        BigInteger biExp = Convert.toBigInteger(exp);
        BigInteger biResult = biData.modPow(biExp, biModulus);
        return biResult.toByteArray();
    }

    public static String encrypt(String pubKeyPem, String plainHex, String padding) {
        if (padding.equals("None")) {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(pubKeyPem.getBytes());
            BCRSAPublicKey publicKey = (BCRSAPublicKey)PemUtil.readPemPublicKey(inputStream);

            BigInteger biData = Util.byteConvertInteger(HexUtil.decodeHex(plainHex));
            BigInteger biResult = biData.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
            return HexUtil.encodeHexStr(biResult.toByteArray(), false);
        }

        String alg = getRsaEncryptPadding(padding);
        String pubKey = Base64.encodeBase64String(readPubKeyFromPem(pubKeyPem));
        RSA rsa = new RSA(alg, null, pubKey);
        return rsa.encryptHex(HexUtil.decodeHex(plainHex), KeyType.PublicKey);
    }

    public static String decrypt(String privKeyPem, String cipherHex, String padding) {
        if (padding.equals("None")) {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(privKeyPem.getBytes());
            BCRSAPrivateCrtKey privateKey = (BCRSAPrivateCrtKey)PemUtil.readPemPrivateKey(inputStream);

            BigInteger biData = Util.byteConvertInteger(HexUtil.decodeHex(cipherHex));
            BigInteger biResult = biData.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
            return HexUtil.encodeHexStr(biResult.toByteArray(), false);
        }

        String alg = getRsaEncryptPadding(padding);
        String privKey = Base64.encodeBase64String(readPrivKeyFromPem(privKeyPem));
        RSA rsa = new RSA(alg, privKey, null);
        byte[] plain = rsa.decrypt(HexUtil.decodeHex(cipherHex), KeyType.PrivateKey);
        return HexUtil.encodeHexStr(plain, false);
    }
}
