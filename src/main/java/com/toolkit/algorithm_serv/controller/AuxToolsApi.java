package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.IdUtil;
import com.alibaba.fastjson.JSONObject;

import com.toolkit.algorithm_serv.annotation.SysAuth;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static com.toolkit.algorithm_serv.algorithm.auxtools.RandomHelper.generateRandom;

@RestController
@RequestMapping(value = "/aux")
public class AuxToolsApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public AuxToolsApi(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    @SysAuth
    @GetMapping("/system-time")
    @ResponseBody
    public Object systemTime() {
        try {
            JSONObject jsonOS = new JSONObject();
            jsonOS.put("time", DateUtil.now());   //"2021-01-21 16:14:12"
            return responseHelper.success(jsonOS);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

    @GetMapping("/uuid")
    @ResponseBody
    public Object generateUUID(@RequestParam(value = "simple", required = false) String simple) {
        try {

//            System.out.println("UUID.fromString "+  UUID.fromString(UUID.randomUUID().toString()));
//            System.out.println("UUID.randomUUID "+  UUID.randomUUID());

            JSONObject jsonOS = new JSONObject();
            if (StrAuxUtils.isValid(simple)) {
                jsonOS.put("uuid", IdUtil.simpleUUID());
            } else {
                jsonOS.put("uuid", IdUtil.randomUUID());
            }
            return responseHelper.success(jsonOS);

        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }

    }

    //获取指定字节数的随机数，默认8字节，最少1字节，最多256字节。
    @GetMapping("/random")
    @ResponseBody
    public Object random(@RequestParam(value = "size", required = false) int randomLen) {
        try {
//TODO 种子
            JSONObject jsonOS = new JSONObject();
            jsonOS.put("size", randomLen);
            jsonOS.put("random", generateRandom(randomLen));
//            jsonOS.put("random1", RandomUtil.randomString(randomLen));
//            jsonOS.put("random2", RandomUtil.randomStringUpper(randomLen));

            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_RANDOM, e.getMessage());
        }
    }

}
