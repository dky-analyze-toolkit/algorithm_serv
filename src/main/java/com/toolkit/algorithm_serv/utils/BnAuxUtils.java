package com.toolkit.algorithm_serv.utils;

import cn.hutool.core.util.NumberUtil;
import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONObject;
import com.google.common.math.BigIntegerMath;
import com.google.common.base.Preconditions;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.NoSuchAlgorithmException;

public class BnAuxUtils {
    public static JSONObject packResultJson(BigInteger biResult) {
        JSONObject jsonResult = new JSONObject();
        jsonResult.put("hex", biResult.toString(16));
        jsonResult.put("dec", biResult.toString(10));

        return jsonResult;
    }

    public static BigInteger hex2BigInteger(String hex) {
        // hex = StrUtil.removeAll(hex, ' ', '\r', '\n', '\t', 'x', 'X', ',');
        hex = StrUtil.removeAll(hex, ' ', '\r', '\n', '\t');
        return new BigInteger(hex, 16);
    }

    public static JSONObject biPowModulus(String xHex, String yHex, String modulusHex) {
        BigInteger biX = hex2BigInteger(xHex);
        BigInteger biY = hex2BigInteger(yHex);
        BigInteger biModulus = hex2BigInteger(modulusHex);
        BigInteger biResult;
        JSONObject jsonObject = new JSONObject();

        biResult = biX.modPow(biY, biModulus);
        jsonObject.put("operation", "(x ^ y) % m = ?");

        jsonObject.put("result", packResultJson(biResult));
        jsonObject.put("x", packResultJson(biX));
        jsonObject.put("y", packResultJson(biY));
        jsonObject.put("m", packResultJson(biModulus));
        return jsonObject;
    }

    public static JSONObject biRsaD(String pHex, String qHex, String eHex) {
        BigInteger biP = hex2BigInteger(pHex);
        BigInteger biQ = hex2BigInteger(qHex);
        BigInteger biE = hex2BigInteger(eHex);

        BigInteger biModulus = biP.subtract(BigInteger.ONE).multiply(biQ.subtract(BigInteger.ONE));
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

    private static void checkNotTooBig(int value, int max) {
        Preconditions.checkArgument(value <= max, "数值太大，谨慎操作，建议取值【0--%s】", max);
    }

    public static JSONObject biCalcXY(String operation, String xHex, String yHex) throws NoSuchAlgorithmException {
        BigInteger biX = hex2BigInteger(xHex);
        BigInteger biY = hex2BigInteger(yHex);
        BigInteger biResult;

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("x", packResultJson(biX));
        jsonObject.put("y", packResultJson(biY));

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
            biResult = biX.subtract(BigInteger.ONE).multiply(biY.subtract(BigInteger.ONE));
            jsonObject.put("operation", "(x-1) * (y-1) = ?");
        } else if (operation.equals("bit-and")) {
            biResult = biX.and(biY);
            jsonObject.put("operation", "x & y = ?");
        } else if (operation.equals("bit-or")) {
            biResult = biX.or(biY);
            jsonObject.put("operation", "x | y = ?");
        } else if (operation.equals("bit-xor")) {
            biResult = biX.xor(biY);
            jsonObject.put("operation", "x ^ y = ?");

        } else if (operation.equals("pow")) {
            checkNotTooBig(biY.intValue(), 100);
            biResult = biX.pow(biY.intValue());
            jsonObject.put("operation", "x pow(y) = ?");

        } else if (operation.equals("is-prime")) {
            checkNotTooBig(biY.intValue(), 1000);
            boolean isPrime = biX.isProbablePrime(biY.intValue());
            jsonObject.put("operation", "是否质数：可能是 / 否");
            jsonObject.put("result", isPrime ? "可能是" : "否");
            return jsonObject;
        } else if (operation.equals("divide-mod")) {
            BigInteger[] biRv = biX.divideAndRemainder(biY);
            jsonObject.put("operation", "x / y = quotient (remainder)");
            jsonObject.put("quotient", packResultJson(biRv[0]));
            jsonObject.put("remainder", packResultJson(biRv[1]));
            return jsonObject;
        } else {
            throw new NoSuchAlgorithmException(String.format("不支持【%s】计算操作", operation));
        }

        jsonObject.put("result", packResultJson(biResult));
        return jsonObject;
    }

    public static JSONObject biSingleAction(String operation, String xHex) throws NoSuchAlgorithmException {
        BigInteger biX = hex2BigInteger(xHex);
        BigInteger biResult;

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("x", packResultJson(biX));

        if (operation.equals("bit-not")) {
            byte[] x = biX.toByteArray();
            for (int i=0; i<x.length; i++) {
                x[i] = (byte) ~x[i];
            }
            biResult = new BigInteger(1, x);
            jsonObject.put("operation", "~x = ?");
        } else if (operation.equals("sqrt")) {
            biResult = BigIntegerMath.sqrt(biX, RoundingMode.CEILING);
            jsonObject.put("operation", "sqrt(x) = ?");
        } else {
            throw new NoSuchAlgorithmException(String.format("不支持【%s】计算操作", operation));
        }

        jsonObject.put("result", packResultJson(biResult));
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
