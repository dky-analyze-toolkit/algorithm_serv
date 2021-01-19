package com.toolkit.algorithm_serv.algorithm.hash;

import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import com.toolkit.algorithm_serv.utils_ex.Util;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.SM3Digest;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

public class HashHelper {

    public static String digest(String plainhex, String alg) {
        Map<String,String> algMap = new HashMap<String,String>();
        algMap.put("MD5", "MD5");
        algMap.put("SHA1", "SHA1");
        algMap.put("SHA256", "SHA-256");
        algMap.put("SHA384", "SHA-384");
        algMap.put("SHA512", "SHA-512");
        algMap.put("SM3", "SM3");

        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algMap.get(alg));
            byte[] byte_msg = Util.hexToByte(plainhex);
            byte[] cipherBytes = messageDigest.digest(byte_msg);
            String cipherStr = Hex.encodeHexString(cipherBytes);

            return cipherStr.toUpperCase();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] sm3(byte[] src_bytes) {
        byte[] hash_bytes = new byte[32];
        SM3Digest sm3 = new SM3Digest();
        sm3.update(src_bytes, 0, src_bytes.length);
        sm3.doFinal(hash_bytes, 0);
        return hash_bytes;
    }

    public static String sm3(String srchex) {
        byte[] hash_bytes = new byte[32];
        byte[] src_bytes = Util.hexToByte(srchex);
        hash_bytes = sm3(src_bytes);
        return StrAuxUtils.bytesToHexString(hash_bytes).toUpperCase();
    }

}
