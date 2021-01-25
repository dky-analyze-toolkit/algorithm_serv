package com.toolkit.algorithm_serv.algorithm.hash;

import com.google.common.base.Preconditions;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import com.toolkit.algorithm_serv.utils_ex.Util;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.SM3Digest;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.List;

public class HashHelper {

    private static final Multimap<String, String> algMap = ArrayListMultimap.create();
    static {
        algMap.put("MD5", "MD5");
        algMap.put("SHA1", "SHA1");
        algMap.put("SHA224", "SHA-224");
        algMap.put("SHA256", "SHA-256");
        algMap.put("SHA384", "SHA-384");
        algMap.put("SHA512", "SHA-512");
        algMap.put("SM3", "SM3");
    }

    public static String digest(String plainhex, String alg)throws IllegalArgumentException  {
        Preconditions.checkArgument(algMap.containsKey(alg), "不能识别【%s】算法", alg);

        try {
            String cipherStr = null;
            if(algMap.get(alg).toString().equals("[SM3]"))
            {
                cipherStr = sm3(plainhex);
            }
            else
            {
                MessageDigest messageDigest = MessageDigest.getInstance(algMap.get(alg).toString().replace("[","").replace("]",""));
                byte[] byteMsg = Util.hexToByte(plainhex);
                byte[] cipherBytes = messageDigest.digest(byteMsg);
                cipherStr = Hex.encodeHexString(cipherBytes);
            }
            System.out.println(algMap.get(alg)+":"+cipherStr.toUpperCase());

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

    public static String sm3(String srchex) {
        byte[] hashBytes = new byte[32];
        byte[] srcBytes = Util.hexToByte(srchex);
        hashBytes = sm3(srcBytes);
        return StrAuxUtils.bytesToHexString(hashBytes).toUpperCase();
    }

}
