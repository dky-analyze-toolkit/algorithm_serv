package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.CryptoException;
import cn.hutool.crypto.symmetric.Vigenere;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Strings;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.ExtSymCryptHelper;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.SymCryptHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.InvalidKeyException;

@RestController
@RequestMapping(value = "/crypto/sym-alg")
public class SymCryptApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public SymCryptApi(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    @GetMapping("/generate-key")
    @ResponseBody
    public Object symGenerateKey(
            @RequestParam("alg") String alg,
            @RequestParam("key_bits") int keyBits
    ) {
        try {
            String keyHex = SymCryptHelper.generateKeyHex(alg, keyBits);
            JSONObject jsonKey = new JSONObject();
            jsonKey.put("alg", alg);
            jsonKey.put("key", keyHex);
            jsonKey.put("size", keyHex.length() / 2);
            jsonKey.put("bits", keyHex.length() / 2 * 8);
            jsonKey.put("key_b64", Base64.encode(keyHex));
            return responseHelper.success(jsonKey);
        } catch (IllegalArgumentException e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_ALG_PARAM, e.getMessage());
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }

    }

    @GetMapping("/{crypt}")
    @ResponseBody
    public Object doCrypt(
            @PathVariable("crypt") String crypt,
            @RequestParam(value = "alg") String alg,
            @RequestParam(value = "mode") String mode,
            @RequestParam(value = "padding") String padding,
            @RequestParam(value = "key") String key,
            @RequestParam(value = "iv", required = false, defaultValue = "") String iv,
            @RequestParam(value = "plain_hex", required = false) String plainHex,
            @RequestParam(value = "cipher_hex", required = false) String cipherHex
    ) {
        try {
            JSONObject jsonResult = new JSONObject();
            String result = "";
            if (crypt.equals("encrypt")) {
                if (Strings.isNullOrEmpty(plainHex)) {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PLAIN);
                }
                result = SymCryptHelper.encrypt(alg, mode, padding, plainHex, key, iv);
                jsonResult.put("cipher_hex", result);
                jsonResult.put("cipher_b64", Base64.encode(result));
            } else if (crypt.equals("decrypt")) {
                if (Strings.isNullOrEmpty(cipherHex)) {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_CIPHER);
                }
                result = SymCryptHelper.decrypt(alg, mode, padding, cipherHex, key, iv);
                jsonResult.put("plain_hex", result);
                jsonResult.put("plain_b64", Base64.encode(result));
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
            }

            jsonResult.put("size", result.length() / 2);
            jsonResult.put("bits", result.length() / 2 * 8);
            return responseHelper.success(jsonResult);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_ALG_PARAM, e.getMessage());
        } catch (CryptoException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_CRYPT, e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

    @GetMapping("/rc4/{crypt}")
    @ResponseBody
    public Object doRC4Crypt(
            @PathVariable("crypt") String crypt,
            @RequestParam(value = "key") String key,
            @RequestParam(value = "plain_hex", required = false) String plainHex,
            @RequestParam(value = "cipher_hex", required = false) String cipherHex
    ) {
        try {
            JSONObject jsonResult = new JSONObject();
            String result = "";
            if (crypt.equals("encrypt")) {
                result = ExtSymCryptHelper.encrypt("RC4", plainHex, key);
                jsonResult.put("cipher_hex", result);
                jsonResult.put("cipher_b64", Base64.encode(result));
            } else if (crypt.equals("decrypt")) {
                result = ExtSymCryptHelper.decrypt("RC4", cipherHex, key);
                jsonResult.put("plain_hex", result);
                jsonResult.put("plain_b64", Base64.encode(result));
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
            }
            jsonResult.put("size", result.length() / 2);
            jsonResult.put("bits", result.length() / 2 * 8);
            return responseHelper.success(jsonResult);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_ALG_PARAM, e.getMessage());
        } catch (CryptoException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_CRYPT, e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

    @PostMapping("/vigenere/{crypt}")
    @ResponseBody
    public Object doVigenereCrypt(
            @PathVariable("crypt") String crypt,
            @RequestParam(value = "key") String key,
            @RequestParam(value = "plain_str", required = false) String plainStr,
            @RequestParam(value = "cipher_str", required = false) String cipherStr
    ) {
        try {
            JSONObject jsonResult = new JSONObject();
            String result = "";
            if (crypt.equals("encrypt")) {
                result = ExtSymCryptHelper.encrypt("Vigenere", plainStr, key);
                jsonResult.put("cipher_str", result);
            } else if (crypt.equals("decrypt")) {
                result = ExtSymCryptHelper.decrypt("Vigenere", cipherStr, key);
                jsonResult.put("plain_str", result);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
            }
            jsonResult.put("length", result.length());
            return responseHelper.success(jsonResult);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_ALG_PARAM, e.getMessage());
        } catch (CryptoException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_CRYPT, e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

}
