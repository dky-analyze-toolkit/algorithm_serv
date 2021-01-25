package com.toolkit.algorithm_serv.algorithm.pboc;

import java.security.GeneralSecurityException;

/**
 * 关键字：Java MAC计算
 *
 * 为了检查通讯报文是否被篡改，常需要在报文中加上一个MAC（Message Authentication Code，报文校验码）。
 *
 * 在 JDK 1.4里，已包含一个 Mac 类（javax.crypto.Mac），可以生成MAC。 但它是参照HMAC（Hash-based Message Authentication Code，基于散列的消息验证代码）实现的。 有时，需要采用ANSI-X9.9算法计算MAC。
 *
 * 1. 算法描述 参与ANSI X9.9 MAC计算的数据主要由三部分产生：初始数据、原始数据、补位数据。
 * 1) 算法定义：采用DEC CBC（zeroICV）或ECB算法
 * 2) 初始数据：0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
 * 3) 原始数据:
 * 4) * 补位数据：若原始数据不是8的倍数,则右补齐0x00；若原始数据位8的整数倍，则不用补齐0x00。
 * 5) 密钥: MAC密钥
 *
 * MAC的产生由以下方式完成：(最后一组数据长度若不足8的倍数，则右补齐0x00；若数据长度为8的整数倍，则无需补充0x00)
 * 初始数据 BLOCK #1 BLOCK #2 BLOCK #3 ... BLOCK #N | | | | | +-----> XOR +---> XOR +---> XOR +---> XOR | | | | | | | DES
 * ---+ DES ---+ DES ---+ DES ---> MAC | | | | KEY KEY KEY KEY
 *
 * 返回 -- 加密后的缓冲区
 */
public class ANSIMacUtils {

    /**
     * ANSI X9.9MAC算法  <br/>
     * (1) ANSI X9.9MAC算法只使用单倍长密钥。  <br/>
     * (2)  MAC数据先按8字节分组，表示为D0～Dn，如果Dn不足8字节时，尾部以字节00补齐。 <br/>
     * (3) 用MAC密钥加密D0，加密结果与D1异或作为下一次的输入。 <br/>
     * (4) 将上一步的加密结果与下一分组异或，然后再用MAC密钥加密。<br/>
     * (5) 直至所有分组结束，取最后结果的左半部作为MAC。<br/>
     * 采用x9.9算法计算MAC (Count MAC by ANSI-x9.9).
     *
     * @param key  8字节密钥数据
     * @param data 待计算的缓冲区
     * @throws GeneralSecurityException
     */
    public static byte[] calculateANSIX9_9MAC(byte[] key, byte[] data) throws GeneralSecurityException {

        final int dataLength = data.length;
        final int lastLength = dataLength % 8;
        final int lastBlockLength = lastLength == 0 ? 8 : lastLength;
        final int blockCount = dataLength / 8 + (lastLength > 0 ? 1 : 0);

        // 拆分数据（8字节块/Block）
        byte[][] dataBlock = new byte[blockCount][8];
        for (int i = 0; i < blockCount; i++) {
            int copyLength = i == blockCount - 1 ? lastBlockLength : 8;
            System.arraycopy(data, i * 8, dataBlock[i], 0, copyLength);
        }

        byte[] desXor = new byte[8];
        for (int i = 0; i < blockCount; i++) {
            byte[] tXor = DesUtils.xOr(desXor, dataBlock[i]);
            desXor = DesUtils.encryptByDesEcb(tXor, key); // DES加密
        }
        return desXor;
    }

    /**
     * 采用ANSI x9.19算法计算MAC (Count MAC by ANSI-x9.19).<br/>
     * 将ANSI X9.9的结果做如下计算<br/>
     * (6) 用MAC密钥右半部解密(5)的结果。 <br/>
     * (7) 用MAC密钥左半部加密(6)的结果。<br/>
     * (8) 取(7)的结果的左半部作为MAC。<br/>
     * @param key  16字节密钥数据
     * @param data 待计算的缓冲区
     * @throws GeneralSecurityException
     */
    public static byte[] calculateANSIX9_19MAC(byte[] key, byte[] data) throws GeneralSecurityException {
        if (key == null || data == null)
            return null;

        if (key.length != 16) {
            throw new RuntimeException("秘钥长度错误.");
        }

        byte[] keyLeft = new byte[8];
        byte[] keyRight = new byte[8];
        System.arraycopy(key, 0, keyLeft, 0, 8);
        System.arraycopy(key, 8, keyRight, 0, 8);

        byte[] result99 = calculateANSIX9_9MAC(keyLeft, data);

        byte[] resultTemp = DesUtils.decryptByDesEcb(result99, keyRight);
        return DesUtils.encryptByDesEcb(resultTemp, keyLeft);
    }

}