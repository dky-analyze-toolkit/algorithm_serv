package com.toolkit.algorithm_serv.utils;

import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONObject;
import com.google.common.math.BigIntegerMath;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class BnAuxUtils {
    private static JSONObject packResultJson(BigInteger biResult) {
        JSONObject jsonResult = new JSONObject();
        jsonResult.put("hex", biResult.toString(16));
        jsonResult.put("dec", biResult.toString(10));

        return jsonResult;
    }

    public static JSONObject biPowModulus(String xHex, String yHex, String modulusHex) {
        BigInteger biX = new BigInteger(xHex, 16);
        BigInteger biY = new BigInteger(yHex, 16);
        BigInteger biModulus = new BigInteger(modulusHex, 16);
        BigInteger biResult;
        JSONObject jsonObject = new JSONObject();

        biResult = biX.modPow(biY, biModulus);
        jsonObject.put("operation", "(x ^ y) % m = ?");

        JSONObject jsonResult = packResultJson(biResult);
        jsonObject.put("result", jsonResult);
        jsonObject.put("x_dec", biX.toString(10));
        jsonObject.put("y_dec", biY.toString(10));
        jsonObject.put("m_dec", biModulus.toString(10));
        return jsonObject;
    }

    public static JSONObject biRsaD(String pHex, String qHex, String eHex) {
        pHex = StrUtil.removeAll(pHex, ' ');
        qHex = StrUtil.removeAll(qHex, ' ');
        eHex = StrUtil.removeAll(eHex, ' ');
        BigInteger biP = new BigInteger(pHex, 16);
        BigInteger biQ = new BigInteger(qHex, 16);
        BigInteger biE = new BigInteger(eHex, 16);

        BigInteger biOne = new BigInteger("1");
        BigInteger biModulus = biP.subtract(biOne).multiply(biQ.subtract(biOne));
        BigInteger biN = biP.multiply(biQ);
        BigInteger biD = biE.modInverse(biModulus);
        BigInteger biDP = biD.mod(biP.subtract(BigInteger.ONE));
        BigInteger biDQ = biD.mod(biQ.subtract(BigInteger.ONE));
        BigInteger biQInv = biQ.modInverse(biP);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("operation", "RSA_D(P, Q, E) = ?");

        jsonObject.put("rsa_n", packResultJson(biN));
        jsonObject.put("rsa_d", packResultJson(biD));
        jsonObject.put("rsa_dp", packResultJson(biDP));
        jsonObject.put("rsa_dq", packResultJson(biDQ));
        jsonObject.put("rsa_qinv", packResultJson(biQInv));
        jsonObject.put("rsa_p", packResultJson(biP));
        jsonObject.put("rsa_q", packResultJson(biQ));
        jsonObject.put("rsa_e", packResultJson(biE));
        return jsonObject;
    }

    public static JSONObject biCalc(String operation, String xHex, String yHex) throws NoSuchAlgorithmException {
        BigInteger biX = new BigInteger(xHex, 16);
        BigInteger biY = new BigInteger(yHex, 16);
        BigInteger biResult;

        JSONObject jsonObject = new JSONObject();
        if (operation.equals("add")) {
            biResult = biX.add(biY);
            jsonObject.put("operation", "x + y = ?");
        } else if (operation.equals("subtract")) {
            biResult = biX.subtract(biY);
            jsonObject.put("operation", "x - y = ?");
        } else if (operation.equals("multiply")) {
            biResult = biX.multiply(biY);
            jsonObject.put("operation", "x * y = ?");
        } else if (operation.equals("divide")) {
            biResult = biX.divide(biY);
            jsonObject.put("operation", "x / y = ?");
        } else if (operation.equals("gcd")) {
            biResult = biX.gcd(biY);
            jsonObject.put("operation", "gcd(x, y) = ?");
        } else if (operation.equals("mod")) {
            biResult = biX.mod(biY);
            jsonObject.put("operation", "x % y = ?");
        } else if (operation.equals("mod-inverse")) {
            biResult = biX.modInverse(biY);
            jsonObject.put("operation", "(a * x) mod y = 1, a = ?");
        } else if (operation.equals("multiply-1")) {
            BigInteger biOne = new BigInteger("1");
            biResult = biX.subtract(biOne).multiply(biY.subtract(biOne));
            jsonObject.put("operation", "(x-1) * (y-1) = ?");
        } else {
            throw new NoSuchAlgorithmException(String.format("不支持【%s】计算操作", operation));
        }

        JSONObject jsonResult = packResultJson(biResult);
        jsonObject.put("result", jsonResult);
        jsonObject.put("x_dec", biX.toString(10));
        jsonObject.put("y_dec", biY.toString(10));
        return jsonObject;
    }
    //
    // public static JSONObject biAdd(String augendHex, String addendHex) {
    //     BigInteger biAugend = new BigInteger(augendHex, 16);
    //     BigInteger biAddend = new BigInteger(addendHex, 16);
    //     BigInteger biResult = biAugend.add(biAddend);
    //
    //     JSONObject jsonResult = packResultJson(biResult);
    //     jsonResult.put("augend_dec", biAugend.toString(10));
    //     jsonResult.put("addend_dec", biAddend.toString(10));
    //     return jsonResult;
    // }
    //
    // public static String biAddHex(String augendHex, String addendHex) {
    //     BigInteger biAugend = new BigInteger(augendHex, 16);
    //     BigInteger biAddend = new BigInteger(addendHex, 16);
    //     BigInteger biSum = biAugend.add(biAddend);
    //     return biSum.toString(16);
    // }
    //
    // public static JSONObject biSub(String minuendHex, String subtrahendHex) {
    //     BigInteger biMinuend = new BigInteger(minuendHex, 16);
    //     BigInteger biSubtrahend = new BigInteger(subtrahendHex, 16);
    //     BigInteger biResult = biMinuend.subtract(biSubtrahend);
    //
    //     JSONObject jsonResult = packResultJson(biResult);
    //     jsonResult.put("minuend_dec", biMinuend.toString(10));
    //     jsonResult.put("subtrahend_dec", biSubtrahend.toString(10));
    //     return jsonResult;
    // }
    //
    // public static JSONObject biMultiply(String multiplicandHex, String multiplierHex) {
    //     BigInteger biMultiplicand = new BigInteger(multiplicandHex, 16);
    //     BigInteger biMultiplier = new BigInteger(multiplierHex, 16);
    //     BigInteger biResult = biMultiplicand.multiply(biMultiplier);
    //
    //     JSONObject jsonResult = packResultJson(biResult);
    //     jsonResult.put("multiplicand_dec", biMultiplicand.toString(10));
    //     jsonResult.put("multiplier_dec", biMultiplier.toString(10));
    //     return jsonResult;
    // }
    //
    // public static JSONObject biDivide(String dividendHex, String divisorHex) {
    //     BigInteger biDividend = new BigInteger(dividendHex, 16);
    //     BigInteger biDivisor = new BigInteger(divisorHex, 16);
    //     BigInteger biResult = biDividend.divide(biDivisor);
    //
    //     JSONObject jsonResult = packResultJson(biResult);
    //     jsonResult.put("dividend_dec", biDividend.toString(10));
    //     jsonResult.put("divisor_dec", biDivisor.toString(10));
    //     return jsonResult;
    // }

    // public static JSONObject biAdd()
    //
    // public static BigInteger convertBigInt(byte[] b) {
    //     if (b[0] < 0) {
    //         byte[] temp = new byte[b.length + 1];
    //         temp[0] = 0;
    //         System.arraycopy(b, 0, temp, 1, b.length);
    //         return new BigInteger(temp);
    //     }
    //     return new BigInteger(b);
    // }
    //
    // public static BigInteger hex2BigInt(String hex) {
    //
    // }
}
