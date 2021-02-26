package com.toolkit.algorithm_serv.controller;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.hash.HashHelper;
import com.toolkit.algorithm_serv.algorithm.hmac.HMacHelper;
import com.toolkit.algorithm_serv.global.annotation.*;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


@RestController
@SysAuth
@RequestMapping(value = "/crypto")
public class HashApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;
    private final ExceptionHelper exceptionHelper;

    @Autowired
    public HashApi(ResponseHelper responseHelper, ExceptionHelper exceptionHelper) {
        this.responseHelper = responseHelper;
        this.exceptionHelper = exceptionHelper;
    }

    /**
     * 1.0 hash
     * 对原文计算摘要值，支持算法：MD5、SHA1、SHA256、SHA384、SHA512、SM3
     * alg: 参数指定hash算法（多个，用逗号分隔, 空值:计算全部）。单个接口返回所有指定的hash结果。
     *
     * @return
     */
    @PostMapping("/hash")
    @ResponseBody
    public Object hash(@RequestParam("src_hex") String srcHex,
                       @RequestParam("alg") String alg) {

        try {
            JSONObject jsonOS = new JSONObject();
            alg = alg.toUpperCase();

            if (alg.isEmpty()) {
                alg = "MD5,SHA1,SHA224,SHA256,SHA384,SHA512,SM3";
            } else {
                alg = alg.replaceAll(" ", "");
            }
            String[] alg_list = alg.split(",");
            for (String item : alg_list) {
                if (item.isEmpty())
                    continue;
                jsonOS.put(item, HashHelper.digest(srcHex, item));
            }
            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_HASH, e.getMessage());
        }
    }

    @PostMapping("/hmac")
    @ResponseBody
    public Object hash(@RequestParam("plain_hex") String plainHex,
                       @RequestParam("alg") String alg,
                       @RequestParam("key_hex") String keyHex) {

        try {
            JSONObject jsonResult = HMacHelper.hmac(alg, plainHex, keyHex);
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }
}
