package com.toolkit.algorithm_serv.algorithm.sym_crypt;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import org.apache.commons.lang3.StringUtils;

import java.security.InvalidKeyException;
import java.util.List;
import java.util.Map;

public class SymCryptHelper {
    // private static final Map<String, Boolean> validKeySizeMap = new HashMap<>(5);
    // static {
    //     validKeySizeMap.put("DES", Boolean.TRUE);
    // }
    // private static final List<String> algLists = Lists.newArrayList("AES", "DES", "DESede");

    private static final Multimap<String, Integer> validKeySizeMap = ArrayListMultimap.create();
    static {
        validKeySizeMap.put("AES", 128);
        validKeySizeMap.put("AES", 192);
        validKeySizeMap.put("AES", 256);
        validKeySizeMap.put("DES", 56);
        validKeySizeMap.put("DESede", 168);
        // validKeySizeMap.put("SM4", 128);
    }

    public static boolean findAlgKeySize(String alg, Integer keySize) {
        return validKeySizeMap.get(alg).contains(keySize);
    }

    public static byte[] generateKey(String alg, int keyLen) throws IllegalArgumentException {
        Integer keySize = Integer.valueOf(keyLen);
        Preconditions.checkArgument(!Strings.isNullOrEmpty(alg), "未指定算法");
        Preconditions.checkArgument(validKeySizeMap.containsKey(alg), "不能识别%s算法", alg);
        Preconditions.checkArgument(findAlgKeySize(alg, keySize), "%s算法不支持密钥长度：%s位", alg, keyLen);
        // Preconditions.

        byte[] key = null;

        SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue(), keyLen);
        return key;
    }

    public static String generateKeyHex(String alg, int keyLen) throws InvalidKeyException{
        return StrAuxUtils.bytesToHexString(SymCryptHelper.generateKey(alg, keyLen));
    }
}
