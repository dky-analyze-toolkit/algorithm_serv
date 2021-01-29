package com.toolkit.algorithm_serv.algorithm.hmac;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.crypto.digest.HMac;
import cn.hutool.crypto.digest.HmacAlgorithm;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.toolkit.algorithm_serv.algorithm.auxtools.JsonResultHelper;

import java.util.List;
import java.util.Map;

public class HMacHelper {
    private static final Map<String, HmacAlgorithm> hmacAlgsMap = ImmutableMap.<String, HmacAlgorithm>builder()
            .put("MD5", HmacAlgorithm.HmacMD5)
            .put("SHA1", HmacAlgorithm.HmacSHA1)
            .put("SHA256", HmacAlgorithm.HmacSHA256)
            .put("SHA384", HmacAlgorithm.HmacSHA384)
            .put("SHA512", HmacAlgorithm.HmacSHA512)
            .put("SM3", HmacAlgorithm.HmacSM3)
            .build();

    // private static String[] getAlgs() {
    //     return hmacAlgsMap.forEach();
    // }

    private static HmacAlgorithm getAlg(String algName) {
        return hmacAlgsMap.get(algName);
    }

    public static JSONObject hmac(String algs, String plainHex, String keyHex) {
        if (Strings.isNullOrEmpty(algs)) {
            algs = "MD5,SHA1,SHA224,SHA256,SHA384,SHA512,SM3";
        }
        byte[] key = HexUtil.decodeHex(keyHex);
        byte[] plain = HexUtil.decodeHex(plainHex);
        JSONObject jsonResult = new JSONObject();

        Splitter splitter = Splitter.on(",").trimResults().omitEmptyStrings();
        List<String> a = splitter.splitToList(algs);
        // String[] algList = splitter.split(algs);
        for (String algName: splitter.split(algs)) {
            HmacAlgorithm hmacAlg = getAlg(algName);
            if (hmacAlg != null) {
                HMac hmac = new HMac(hmacAlg, key);
                String hmacHex = hmac.digestHex(plain);
                jsonResult.put(hmacAlg.getValue(), JsonResultHelper.jsonHexAndB64(hmacHex));
            } else {
                jsonResult.put("hmac" + algName, "不支持该算法");
            }
        }
        // HMac hmac = new HMac(HmacAlgorithm.HmacMD5, key);

        return jsonResult;
    }

    public static byte[] hmac(HmacAlgorithm alg, String plain, byte[] key) {
        HMac hmac = new HMac(alg, key);
        return hmac.digest(plain);
    }

    public static byte[] sha1hmac(String plain, byte[] key) {
        return hmac(HmacAlgorithm.HmacSHA1, plain, key);
    }
}
