package com.toolkit.algorithm_serv.algorithm.b64;

import com.toolkit.algorithm_serv.utils.StrAuxUtils;

import java.util.Base64;

public class Base64Coding {
    static public String encode(byte[] originBytes) {
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(originBytes);
    }

    static public String encodeFromHexString(String originText) {
        byte[] originBytes = StrAuxUtils.hexStringToBytes(originText);
        return encode(originBytes);
    }

    static public byte[] decode(String encodedText) {
        try {
            Base64.Decoder decoder = Base64.getDecoder();
            return decoder.decode(encodedText);
        } catch (Exception e) {
            return new byte[1];
        }
    }

    static public String decodeToHexString(String encodedText) {
        byte[] originBytes = decode(encodedText);
        return StrAuxUtils.bytesToHexString(originBytes);
    }
}
