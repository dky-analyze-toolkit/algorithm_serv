package com.toolkit.algorithm_serv.algorithm.hash;

import com.google.common.base.Preconditions;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import com.toolkit.algorithm_serv.utils_ex.Util;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.SM3Digest;

import java.security.MessageDigest;

public class HashHelper {

    private static final Multimap<String, String> algMultiMap = ArrayListMultimap.create();

    static {
        algMultiMap.put("MD5", "MD5");
        algMultiMap.put("SHA1", "SHA1");
        algMultiMap.put("SHA224", "SHA-224");
        algMultiMap.put("SHA256", "SHA-256");
        algMultiMap.put("SHA384", "SHA-384");
        algMultiMap.put("SHA512", "SHA-512");
        algMultiMap.put("SM3", "SM3");
    }

    public static String digest(String srcHex, String alg) throws IllegalArgumentException {
        Preconditions.checkArgument(algMultiMap.containsKey(alg), "不能识别【%s】算法", alg);

        try {
            String cipherStr = null;

            if (algMultiMap.get(alg).toString().equals("[SM3]")) {
                cipherStr = sm3(srcHex);
            } else {
                MessageDigest messageDigest = MessageDigest.getInstance(algMultiMap.get(alg).toString().replace("[", "").replace("]", ""));
                byte[] byteMsg = Util.hexToByte(srcHex);
                byte[] cipherBytes = messageDigest.digest(byteMsg);
                cipherStr = Hex.encodeHexString(cipherBytes);
            }
            System.out.println(algMultiMap.get(alg) + ":" + cipherStr.toUpperCase());

            return cipherStr.toUpperCase();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] sm3(byte[] srcBytes) {
        byte[] hashBytes = new byte[32];
        SM3Digest sm3 = new SM3Digest();
        sm3.update(srcBytes, 0, srcBytes.length);
        sm3.doFinal(hashBytes, 0);
        return hashBytes;
    }

    public static String sm3(String srcHex) {
        byte[] hashBytes = new byte[32];
        byte[] srcBytes = Util.hexToByte(srcHex);
        hashBytes = sm3(srcBytes);
        return StrAuxUtils.bytesToHexString(hashBytes).toUpperCase();
    }

}
