package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Strings;
import com.toolkit.algorithm_serv.algorithm.auxtools.JsonResultHelper;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.ExtSymCryptHelper;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.PBECryptHelper;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.SymCryptHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.TimeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

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

    private Object noSuchCrypt(String crypt) {
        String errMsg = String.format("当前请求的接口，不能识别【%s】功能。", crypt);
        return responseHelper.error(ErrorCodeEnum.ERROR_NO_SUCH_FUNC, errMsg);
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
            JsonResultHelper.jsonPutHex(jsonKey, "key", keyHex);
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
                JsonResultHelper.jsonPutHex(jsonResult, "cipher", result);
            } else if (crypt.equals("decrypt")) {
                if (Strings.isNullOrEmpty(cipherHex)) {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_CIPHER);
                }
                result = SymCryptHelper.decrypt(alg, mode, padding, cipherHex, key, iv);
                JsonResultHelper.jsonPutHex(jsonResult, "plain", result);
            } else {
                return noSuchCrypt(crypt);
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
                JsonResultHelper.jsonPutHex(jsonResult, "cipher", result);
            } else if (crypt.equals("decrypt")) {
                result = ExtSymCryptHelper.decrypt("RC4", cipherHex, key);
                JsonResultHelper.jsonPutHex(jsonResult, "plain", result);
            } else {
                return noSuchCrypt(crypt);
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
                return noSuchCrypt(crypt);
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
            JsonResultHelper.jsonPutHex(jsonResult, "salt", saltHex);
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
            @RequestParam(value = "iteration_count", required = false, defaultValue = "0") int iterationCount,
            @RequestParam(value = "plain_hex", required = false) String plainHex,
            @RequestParam(value = "cipher_hex", required = false) String cipherHex
    ) {
        try {
            JSONObject jsonResult = new JSONObject();
            String result = "";
            if (crypt.equals("encrypt")) {
                result = PBECryptHelper.encrypt(alg, plainHex, password, saltHex, iterationCount);
                JsonResultHelper.jsonPutHex(jsonResult, "cipher", result);
            } else if (crypt.equals("decrypt")) {
                result = PBECryptHelper.decrypt(alg, cipherHex, password, saltHex, iterationCount);
                JsonResultHelper.jsonPutHex(jsonResult, "plain", result);
            } else {
                return noSuchCrypt(crypt);
            }
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/kits/loop/{crypt}")
    @ResponseBody
    public Object doLoopCrypt(
            @PathVariable("crypt") String crypt,
            @RequestParam(value = "alg") String alg,
            @RequestParam(value = "key") String key,
            @RequestParam(value = "iteration_count") int iterationCount,
            @RequestParam(value = "plain_hex", required = false) String plainHex,
            @RequestParam(value = "cipher_hex", required = false) String cipherHex
    ) {
        try {
            if (iterationCount <=0 || iterationCount > 1000000) {
                return responseHelper.error(ErrorCodeEnum.ERROR_LOOP_OUT_OF_RANGE, "循环加解密的次数只允许【1--1,000,000】。");
            }
            JSONObject jsonResult = new JSONObject();
            String result = "";
            // 循环加解密的起始时间
            Date startTime = DateUtil.date();

            if (crypt.equals("encrypt")) {
                result = SymCryptHelper.encryptLoop(alg, plainHex, key, iterationCount);
                JsonResultHelper.jsonPutHex(jsonResult, "cipher", result);
            } else if (crypt.equals("decrypt")) {
                result = SymCryptHelper.decryptLoop(alg, cipherHex, key, iterationCount);
                JsonResultHelper.jsonPutHex(jsonResult, "plain", result);
            } else {
                return noSuchCrypt(crypt);
            }

            // 循环加解密消耗的时间
            jsonResult.put("time_used", TimeUtils.timeUsedFormat(startTime, true));

            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }

    }

}
