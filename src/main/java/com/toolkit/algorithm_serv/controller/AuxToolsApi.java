package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.IdUtil;
import cn.hutool.core.util.RandomUtil;
import com.alibaba.fastjson.JSONObject;

import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static com.toolkit.algorithm_serv.algorithm.auxtools.RandomHelper.generateRandom;
import static com.toolkit.algorithm_serv.algorithm.auxtools.TimeAuxUtils.stamp2time;
import static com.toolkit.algorithm_serv.algorithm.auxtools.TimeAuxUtils.time2stamp;

@RestController
@RequestMapping(value = "/aux")
public class AuxToolsApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public AuxToolsApi(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    @GetMapping("/time-convert/{arg}")
    @ResponseBody
    public Object timeConvert(
            @PathVariable(value = "arg", required = true) String codeAct,
            @RequestParam(value = "time", required = false) String timeStr,
            @RequestParam(value = "stamp", required = false) String stampStr) {
        try{
            if (codeAct.equalsIgnoreCase("time2stamp")) {
                if (StrAuxUtils.isValid(timeStr)) {
                    stampStr = time2stamp(timeStr);
                }
                JSONObject jsonOS = new JSONObject();
                jsonOS.put("stamp", stampStr);
                return responseHelper.success(jsonOS);
            } else if (codeAct.equalsIgnoreCase("stamp2time")) {
                if (StrAuxUtils.isValid(stampStr)) {
                    timeStr = stamp2time(stampStr);
                }
                JSONObject jsonOS = new JSONObject();
                jsonOS.put("time", timeStr);
                return responseHelper.success(jsonOS);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_TIME_CONVERT, "不能识别的参数，arg：" + codeAct);
            }
        }
        catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }

    }

    @GetMapping("/system-time")
    @ResponseBody
    public Object systemTime() {
        try{
            JSONObject jsonOS = new JSONObject();
    //        jsonOS.put("time", DateTime.now()); //"2021-01-21T08:14:12.650+00:00",
            jsonOS.put("time", DateUtil.now());   //"2021-01-21 16:14:12"
            return responseHelper.success(jsonOS);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }

    }

    @GetMapping("/uuid")
    @ResponseBody
    public Object generateUUID(@RequestParam(value = "simple", required = false) String simple) {
        try{
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
