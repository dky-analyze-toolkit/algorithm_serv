package com.toolkit.algorithm_serv.controller;

import com.toolkit.algorithm_serv.algorithm.b64.Base64Coding;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

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
            @PathVariable(value = "arg", required = true)String codeAct,
            @RequestParam(value = "plain_hex", required = false)String plainHex,
            @RequestParam(value = "plain_str", required = false)String plainStr,
            @RequestParam(value = "code_str", required = false)String codeStr) {
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
}
