package com.toolkit.algorithm_serv.algorithm.sym_crypt;

import cn.hutool.core.util.ArrayUtil;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Multimap;

import java.util.Map;

public class ParamsHelper {
    private static final Multimap<String, Integer> validKeySizeMap = ArrayListMultimap.create();
    static {
        validKeySizeMap.put(SymmetricAlgorithm.AES.getValue(), 128);
        validKeySizeMap.put(SymmetricAlgorithm.AES.getValue(), 192);
        validKeySizeMap.put(SymmetricAlgorithm.AES.getValue(), 256);
        validKeySizeMap.put(SymmetricAlgorithm.DES.getValue(), 64);
        // validKeySizeMap.put(SymmetricAlgorithm.DESede.getValue(), 128);
        validKeySizeMap.put(SymmetricAlgorithm.DESede.getValue(), 192);
        validKeySizeMap.put("SM4", 128);
    }

    private static final Map<String, Integer> ivSizeMap = ImmutableMap.<String, Integer>builder()
            .put(SymmetricAlgorithm.AES.getValue(), 128)
            .put(SymmetricAlgorithm.DES.getValue(), 64)
            .put(SymmetricAlgorithm.DESede.getValue(), 64)
            .put("SM4", 128)
            .build();

    private static final Map<String, Mode> modeMap = ImmutableMap.<String, Mode>builder()
            .put("None", Mode.NONE)
            .put("CBC", Mode.CBC)
            .put("CFB", Mode.CFB)
            .put("CTR", Mode.CTR)
            .put("CTS", Mode.CTS)
            .put("ECB", Mode.ECB)
            .put("OFB", Mode.OFB)
            // .put("PCBC", Mode.PCBC)
            .build();

    private static final Map<String, Padding> paddingMap = ImmutableMap.<String, Padding>builder()
            .put("None", Padding.NoPadding)
            .put("Zero", Padding.ZeroPadding)
            .put("ISO10126", Padding.ISO10126Padding)
            // .put("OAEP", Padding.OAEPPadding)
            // .put("PKCS1", Padding.PKCS1Padding)
            .put("PKCS5", Padding.PKCS5Padding)
            // .put("SSL3", Padding.SSL3Padding)
            .build();

    public static boolean isValidKeySize(String alg, int keyBits) {
        return validKeySizeMap.get(alg).contains(Integer.valueOf(keyBits));
    }

    public static void checkAlg(String alg) {
        Preconditions.checkArgument(!Strings.isNullOrEmpty(alg), "未指定算法");
        Preconditions.checkArgument(validKeySizeMap.containsKey(alg), "不能识别【%s】算法", alg);
    }

    public static void checkKeySize(String alg, int keyBits) {
        Preconditions.checkArgument(isValidKeySize(alg, keyBits), "【%s】算法不支持密钥长度：%s 位", alg, keyBits);
    }

    public static void checkMode(String mode) {
        Preconditions.checkArgument(modeMap.containsKey(mode), "不支持【%s】加密模式", mode);
    }

    public static void checkPadding(String padding) {
        Preconditions.checkArgument(paddingMap.containsKey(padding), "不支持【%s】填充/补齐方式", padding);
    }

    public static void checkModePadding(String mode, String padding) {
        checkMode(mode);
        checkPadding(padding);
    }

    public static void checkAlgKeySize(String alg, int keyBits) {
        checkAlg(alg);
        checkKeySize(alg, keyBits);
    }

    public static void checkIVSize(String alg, int ivSize) {
        int size = ivSizeMap.get(alg);
        Preconditions.checkArgument(ivSize >= size, "【%s】算法初始向量长度应为：%s 位", alg, size);
    }

    public static byte[] checkIV(String alg, byte[] iv) {
        int size = ivSizeMap.get(alg);
        Preconditions.checkArgument(iv != null && iv.length >= (size / 8), "【%s】算法初始向量长度应为：%s 位", alg, size);
        if (iv.length > size / 8) {
            return ArrayUtil.resize(iv, size / 8);
        } else {
            return iv;
        }
    }

    public static Mode getMode(String mode) {
        return modeMap.get(mode);
    }

    public static Padding getPadding(String padding) {
        return paddingMap.get(padding);
    }
}
