package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.net.Ipv4Util;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.IdUtil;
import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson.JSONObject;

import com.google.common.base.Strings;
import com.toolkit.algorithm_serv.annotation.SysAuth;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;

import static com.toolkit.algorithm_serv.algorithm.auxtools.RandomHelper.generateRandom;

@RestController
@SysAuth
@RequestMapping(value = "/aux")
public class AuxToolsApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;
    private final ExceptionHelper exceptionHelper;

    @Autowired
    public AuxToolsApi(ResponseHelper responseHelper, ExceptionHelper exceptionHelper) {
        this.responseHelper = responseHelper;
        this.exceptionHelper = exceptionHelper;
    }

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

    @GetMapping("/base-convert")
    @ResponseBody
    public Object baseConvert(@RequestParam("src_number") String srcNumber,
                              @RequestParam("src_radix") int srcRadix,
                              @RequestParam("dest_radix") int destRadix) {
        try {
            JSONObject jsonResult = new JSONObject();
            JSONObject jsonSrc = new JSONObject();
            jsonSrc.put("number", srcNumber);
            jsonSrc.put("radix", srcRadix);

            JSONObject jsonDest = new JSONObject();
            BigInteger src = new BigInteger(srcNumber, srcRadix);
            jsonDest.put("number", src.toString(destRadix));
            jsonDest.put("radix", destRadix);

            jsonResult.put("src", jsonSrc);
            jsonResult.put("dest", jsonDest);

            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @GetMapping("/ip-convert")
    @ResponseBody
    public Object ipConvert(@RequestParam(value = "ip_str", required = false) String ipStr,
                            @RequestParam(value = "ip_num", required = false) long ipNum) {
        try {
            JSONObject jsonResult = new JSONObject();
            if (Strings.isNullOrEmpty(ipStr)) {
                ipStr = Ipv4Util.longToIpv4(ipNum);
            } else {
                ipNum = Ipv4Util.ipv4ToLong(ipStr);
            }
            jsonResult.put("addr", ipStr);
            jsonResult.put("number", ipNum);
            jsonResult.put("hex", HexUtil.toHex(ipNum));
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }
}
