package com.toolkit.algorithm_serv.utils;


import java.util.Random;
import java.util.UUID;

public class StringUtils {
    static public String generatePrintableRandom(int length) {
        String valueBuff = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        StringBuilder stringBuilder = new StringBuilder();
        String authKey = "";
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(valueBuff.length());
            stringBuilder.append(valueBuff.charAt(index));
        }

        return stringBuilder.toString();
    }

    static public boolean isValid(String str) {
        return ((str != null) && (!str.isEmpty()));
    }

    /**
     * 提取字符串中的数字，并转换成整数。支持负数。
     *
     * @param origin 可能带有非数字的字符串
     * @return 提取并转换得到的整数
     */
    static public int extractInt(String origin) {
        String regex = "[^\\d^-]+";
        origin = origin.replaceAll(regex, "");
        return Integer.parseInt(origin);
    }

    /**
     * Convert byte[] to hex string.这里我们可以将byte转换成int，然后利用Integer.toHexString(int)来转换成16进制字符串。
     *
     * @param src byte[] payload
     * @return hex string
     */
    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    /**
     * Convert hex string to byte[]
     *
     * @param hexString the hex string
     * @return byte[]
     */
    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }

    /**
     * Convert char to byte
     *
     * @param c char
     * @return byte
     */
    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    public static String generateUuid() {
        return UUID.randomUUID().toString();
    }

    /**
     * 判定传入的属性字符串里，是否含有指定的属性
     *
     * @param props    属性字符串，含 0 到多个属性
     * @param property 属性（个位正整数，0-9）
     * @return true -- 字符串中含有指定属性
     * false -- 字符串中找不到指定属性
     */
    static public boolean isPropertyExist(String props, int property) {
        if (!StringUtils.isValid(props))
            return false;
        String propertyString = Integer.toString(property);
        return props.contains(propertyString);
    }
}
