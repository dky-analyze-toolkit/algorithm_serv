package com.toolkit.algorithm_serv.algorithm.hash;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.sm4.SM4;
import com.toolkit.algorithm_serv.algorithm.sm4.SM4_Context;
import com.toolkit.algorithm_serv.utils_ex.Util;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.springframework.web.bind.annotation.RequestParam;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;

public class HashHelper {

    public static String digest(String plainhex, String alg) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(alg);
            byte[] byte_msg = Util.hexToByte(plainhex);
            byte[] cipherBytes = messageDigest.digest(byte_msg);
            String cipherStr = Hex.encodeHexString(cipherBytes);

            return cipherStr.toUpperCase();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String sm3(String srchex) {
        byte[] md = new byte[32];
        byte[] msg1 = Util.hexToByte(srchex);
        System.out.println(Util.byteToHex(msg1));
        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg1, 0, msg1.length);
        sm3.doFinal(md, 0);
        String s = new String(org.bouncycastle.util.encoders.Hex.encode(md));
        return s.toUpperCase();
    }


}
