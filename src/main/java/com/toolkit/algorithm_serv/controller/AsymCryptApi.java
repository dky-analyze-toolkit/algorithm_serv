package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.auxtools.JsonResultHelper;
import com.toolkit.algorithm_serv.algorithm.rsa.RSAHelper;
// import com.toolkit.algorithm_serv.global.annotation.SysAuth;
import com.toolkit.algorithm_serv.global.annotation.*;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.TimeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Date;

@RestController
@SysAuth
@RequestMapping(value = "/crypto/asym-alg")
public class AsymCryptApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ExceptionHelper exceptionHelper;
    private final ResponseHelper responseHelper;

    @Autowired
    public AsymCryptApi(ExceptionHelper exceptionHelper, ResponseHelper responseHelper) {
        this.exceptionHelper = exceptionHelper;
        this.responseHelper = responseHelper;
    }

    @GetMapping("/rsa/generate-key")
    @ResponseBody
    public Object rsaGenerateKey(
            @RequestParam("key_bits") int keyBits,
            @RequestParam(value = "rsa_e", required = false, defaultValue = "65537") int rsa_e
    ) throws IOException {
        // 计时
        Date startTime = DateUtil.date();

        JSONObject jsonKey = RSAHelper.generateKeyPairJson(keyBits, rsa_e);

        // 生成密钥和构造数据，整体消耗的时间
        jsonKey.put("time_used", TimeUtils.timeUsedFormat(startTime, true));
        return responseHelper.success(jsonKey);
    }

    @PostMapping("/rsa/read-pem")
    @ResponseBody
    public Object rsaReadPEM(
            @RequestParam("pem") String pem
    ) {
        JSONObject jsonKey = RSAHelper.readPem(pem);
        return responseHelper.success(jsonKey);
    }

    @PostMapping("/rsa/sign")
    @ResponseBody
    public Object rsaSign(
            @RequestParam("sign_alg") String signAlg,
            @RequestParam("priv_key_pem") String privKeyPem,
            @RequestParam("data_hex") String dataHex
    ) {
        String signedHex = RSAHelper.sign(signAlg, privKeyPem, dataHex);
        JSONObject jsonSign = new JSONObject();
        JsonResultHelper.jsonPutHex(jsonSign, "signature", signedHex);
        return responseHelper.success(jsonSign);
    }

    @PostMapping("/rsa/verify")
    @ResponseBody
    public Object rsaVerify(
            @RequestParam("sign_alg") String signAlg,
            @RequestParam("pub_key_pem") String pubKeyPem,
            @RequestParam("data_hex") String dataHex,
            @RequestParam("sign_hex") String signHex
    ) {
        boolean verifyResult = RSAHelper.verify(signAlg, pubKeyPem, dataHex, signHex);
        JSONObject jsonVerify = new JSONObject();
        jsonVerify.put("verify_result", verifyResult);
        return responseHelper.success(jsonVerify);
    }

    @PostMapping("/rsa/encrypt")
    @ResponseBody
    public Object rsaEncrypt(
            @RequestParam("padding") String padding,
            @RequestParam("pub_key_pem") String pubKeyPem,
            @RequestParam("plain_hex") String plainHex
    ) {
        try {
            String cipherHex = RSAHelper.encrypt(pubKeyPem, plainHex, padding);
            JSONObject jsonCipher = new JSONObject();
            JsonResultHelper.jsonPutHex(jsonCipher, "cipher", cipherHex);
            return responseHelper.success(jsonCipher);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }


    @PostMapping("/rsa/decrypt")
    @ResponseBody
    public Object rsaDecrypt(
            @RequestParam("padding") String padding,
            @RequestParam("priv_key_pem") String privKeyPem,
            @RequestParam("cipher_hex") String cipherHex
    ) {
        try {
            String plainHex = RSAHelper.decrypt(privKeyPem, cipherHex, padding);
            JSONObject jsonPlain = new JSONObject();
            JsonResultHelper.jsonPutHex(jsonPlain, "plain", plainHex);
            return responseHelper.success(jsonPlain);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/rsa/attack-d")
    @ResponseBody
    public Object rsaAttackD(
            @RequestParam("rsa_n") String rsaN,
            @RequestParam("rsa_e") String rsaE,
            @RequestParam("rsa_d") String rsaD
    ) {
        try {
            JSONObject jsonResult = RSAHelper.attackRsaD(rsaE, rsaD, rsaN);
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }
}
