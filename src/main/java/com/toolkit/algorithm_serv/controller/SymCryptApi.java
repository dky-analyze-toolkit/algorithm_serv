package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.CryptoException;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Strings;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.ExtSymCryptHelper;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.PBECryptHelper;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.SymCryptHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/crypto/sym-alg")
public class SymCryptApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ExceptionHelper exceptionHelper;
    private final ResponseHelper responseHelper;

    @Autowired
    public SymCryptApi(ExceptionHelper exceptionHelper, ResponseHelper responseHelper) {
        this.exceptionHelper = exceptionHelper;
        this.responseHelper = responseHelper;
    }

    private void putHexSize(JSONObject jsonResult, String hex) {
        jsonResult.put("size", hex.length() / 2);
        jsonResult.put("bits", hex.length() / 2 * 8);
    }

    private void jsonPutHex(JSONObject jsonResult, String key, String value) {
        jsonResult.put(key + "_hex", value);
        jsonResult.put(key + "_b64", Base64.encode(value));
        putHexSize(jsonResult, value);
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
            jsonPutHex(jsonKey, "key", keyHex);
            return responseHelper.success(jsonKey);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/{crypt}")
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
                jsonPutHex(jsonResult, "cipher", result);
            } else if (crypt.equals("decrypt")) {
                if (Strings.isNullOrEmpty(cipherHex)) {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_CIPHER);
                }
                result = SymCryptHelper.decrypt(alg, mode, padding, cipherHex, key, iv);
                jsonPutHex(jsonResult, "plain", result);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
            }

            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/rc4/{crypt}")
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
                jsonPutHex(jsonResult, "cipher", result);
            } else if (crypt.equals("decrypt")) {
                result = ExtSymCryptHelper.decrypt("RC4", cipherHex, key);
                jsonPutHex(jsonResult, "plain", result);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
            }
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
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
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @GetMapping("/pbe/init-salt")
    @ResponseBody
    public Object initPBESalt(@RequestParam(value = "alg") String alg,
                              @RequestParam(value = "salt_size") int saltSize) {
        try {
            String saltHex = PBECryptHelper.initSaltHex(alg, saltSize);
            JSONObject jsonResult = new JSONObject();
            jsonPutHex(jsonResult, "salt", saltHex);
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/pbe/{crypt}")
    @ResponseBody
    public Object doPBECrypt(
            @PathVariable("crypt") String crypt,
            @RequestParam(value = "alg") String alg,
            @RequestParam(value = "password") String password,
            @RequestParam(value = "salt_hex") String saltHex,
            @RequestParam(value = "plain_hex", required = false) String plainHex,
            @RequestParam(value = "cipher_hex", required = false) String cipherHex
    ) {
        try {
            JSONObject jsonResult = new JSONObject();
            String result = "";
            if (crypt.equals("encrypt")) {
                result = PBECryptHelper.encrypt(alg, plainHex, password, saltHex);
                jsonPutHex(jsonResult, "cipher", result);
            } else if (crypt.equals("decrypt")) {
                result = PBECryptHelper.decrypt(alg, cipherHex, password, saltHex);
                jsonPutHex(jsonResult, "plain", result);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
            }
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

}
