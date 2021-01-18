package com.toolkit.algorithm_serv.controller;

import com.toolkit.algorithm_serv.algorithm.sym_crypt.SymCryptHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

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
            @RequestParam("key_size") int keySize) {
        try {
            SymCryptHelper.generateKey(alg, keySize);
            return responseHelper.success();
        } catch (IllegalArgumentException e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_ALG_PARAM, e.getMessage());
        }

    }

}
