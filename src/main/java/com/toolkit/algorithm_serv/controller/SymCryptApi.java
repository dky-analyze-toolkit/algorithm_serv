package com.toolkit.algorithm_serv.controller;

import cn.hutool.crypto.CryptoException;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Strings;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.SymCryptHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.InvalidKeyException;

@RestController
@RequestMapping(value = "/sym_crypt")
public class SymCryptApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public SymCryptApi(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    @GetMapping("/generate_key")
    @ResponseBody
    public Object symGenerateKey(
            @RequestParam("alg") String alg,
            @RequestParam("key_size") int keySize
    ) {
        try {
            JSONObject jsonKey = new JSONObject();
            jsonKey.put("length", keySize);
            jsonKey.put("key", SymCryptHelper.generateKeyHex(alg, keySize));
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
            if (crypt.equals("encrypt")) {
                if (Strings.isNullOrEmpty(plainHex)) {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PLAIN);
                }
                cipherHex = SymCryptHelper.encrypt(alg, mode, padding, plainHex, key, iv);
                jsonResult.put("length", cipherHex.length() / 2 * 8);
                jsonResult.put("cipher", cipherHex);
            } else if (crypt.equals("decrypt")) {
                if (Strings.isNullOrEmpty(cipherHex)) {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_CIPHER);
                }
                plainHex = SymCryptHelper.decrypt(alg, mode, padding, cipherHex, key, iv);
                jsonResult.put("length", plainHex.length() / 2 * 8);
                jsonResult.put("plain", plainHex);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
            }
            return responseHelper.success(jsonResult);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_ALG_PARAM, e.getMessage());
        } catch (CryptoException e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_ENCRYPT, e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

}
