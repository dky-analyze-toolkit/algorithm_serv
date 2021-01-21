package com.toolkit.algorithm_serv.controller;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.b64.Base64Coding;
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
import static com.toolkit.algorithm_serv.utils.StrAuxUtils.generateUuid;
import static com.toolkit.algorithm_serv.utils.TimeUtils.getNowTime;

@RestController
@RequestMapping(value = "/aux")
public class AuxToolsApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public AuxToolsApi(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    @GetMapping("/b64/{arg}")
    @ResponseBody
    public Object base64Code(
            @PathVariable(value = "arg", required = true) String codeAct,
            @RequestParam(value = "plain_hex", required = false) String plainHex,
            @RequestParam(value = "plain_str", required = false) String plainStr,
            @RequestParam(value = "code_str", required = false) String codeStr) {
        if (codeAct.equalsIgnoreCase("encode")) {
            String encodeText = "";
            if (StrAuxUtils.isValid(plainHex)) {
                encodeText = Base64Coding.encodeFromHexString(plainHex);
            } else if (StrAuxUtils.isValid(plainStr)) {
                encodeText = Base64Coding.encode(plainStr.getBytes());
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PARAMETER, "编码时需要填入参数 plain_hex 或 plain_str 。");
            }
            return responseHelper.success(encodeText);
        } else if (codeAct.equalsIgnoreCase("decode")) {
            if (StrAuxUtils.isValid(codeStr)) {
                String decodeHex = Base64Coding.decodeToHexString(codeStr);
                return responseHelper.success(decodeHex);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PARAMETER, "解码时需要填入参数 code_str 。");
            }
        } else {
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_URL, "只支持 base64 编码和解码，不支持：" + codeAct + "。");
        }
    }

    @GetMapping("/timeconvert/{arg}")
    @ResponseBody
    public Object timeconvert(
            @PathVariable(value = "arg", required = true) String codeAct,
            @RequestParam(value = "time", required = false) String timeStr,
            @RequestParam(value = "stamp", required = false) String stampStr) {
        if (codeAct.equalsIgnoreCase("time2stamp")) {
            stampStr = time2stamp(timeStr);
            return responseHelper.success(stampStr);
        } else if (codeAct.equalsIgnoreCase("stamp2time")) {
            timeStr = stamp2time(timeStr);
            return responseHelper.success(timeStr);
        } else {
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_TIME_CONVERT, "检查输入的参数，arg：" + codeAct + " time："+ timeStr + " stamp："+ stampStr);
        }

    }

    @GetMapping("/systime")
    @ResponseBody
    public Object systemTime() {
        JSONObject jsonOS = new JSONObject();
        jsonOS.put("time", getNowTime());
        return responseHelper.success(jsonOS);
    }

    @GetMapping("/uuid")
    @ResponseBody
    public Object generateUUID() {
        JSONObject jsonOS = new JSONObject();
        jsonOS.put("uuid", generateUuid().toUpperCase());
        return responseHelper.success(jsonOS);
    }

    //获取指定字节数的随机数，默认8字节，最少1字节，最多256字节。
    @GetMapping("/random")
    @ResponseBody
    public Object random(@RequestParam(value = "length", required = false) int randomLen) {
        try {
            String random = generateRandom(randomLen);

            JSONObject jsonOS = new JSONObject();
            jsonOS.put("length", randomLen);
            jsonOS.put("random", random);
            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_RANDOM, e.getMessage());
        }
    }

}
