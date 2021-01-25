package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.convert.Convert;
import cn.hutool.core.lang.Validator;
import cn.hutool.core.util.CharsetUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.b64.Base64Coding;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static com.toolkit.algorithm_serv.algorithm.auxtools.TimeAuxUtils.stamp2time;
import static com.toolkit.algorithm_serv.algorithm.auxtools.TimeAuxUtils.time2stamp;

@RestController
@RequestMapping(value = "/transcoding")
public class TransCodingApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public TransCodingApi(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    @PostMapping("/b64/{arg}")
    @ResponseBody
    public Object base64Code(
            @PathVariable(value = "arg", required = true) String codeAct,
            @RequestParam(value = "plain_hex", required = false) String plainHex,
            @RequestParam(value = "plain_str", required = false) String plainStr,
            @RequestParam(value = "code_str", required = false) String codeStr
    ) {
        if (codeAct.equalsIgnoreCase("encode")) {
            String encodeText = "";
            if (StrAuxUtils.isValid(plainHex)) {
                encodeText = Base64Coding.encodeFromHexString(plainHex);
            } else if (StrAuxUtils.isValid(plainStr)) {
                encodeText = Base64Coding.encode(plainStr.getBytes());
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PARAMETER, "编码时需要填入参数 plain_hex 或 plain_str 。");
            }
            JSONObject jsonRes = new JSONObject();
            jsonRes.put("encode_str", encodeText);
            jsonRes.put("length", encodeText.length());
            return responseHelper.success(jsonRes);
        } else if (codeAct.equalsIgnoreCase("decode")) {
            if (StrAuxUtils.isValid(codeStr)) {
                String decodeHex = Base64Coding.decodeToHexString(codeStr);
                JSONObject jsonRes = new JSONObject();
                jsonRes.put("decode_hex", decodeHex);
                jsonRes.put("size", decodeHex.length() / 2);
                return responseHelper.success(jsonRes);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PARAMETER, "解码时需要填入参数 code_str 。");
            }
        } else {
            return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_URL, "只支持 base64 编码和解码，不支持：" + codeAct + "。");
        }
    }

    @GetMapping("/time/{arg}")
    @ResponseBody
    public Object timeConvert(
            @PathVariable(value = "arg", required = true) String codeAct,
            @RequestParam(value = "time", required = false) String timeStr,
            @RequestParam(value = "stamp", required = false) String stampStr) {
        try {
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
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }

    }

    @RequestMapping(value = "/string2hex")
    @ResponseBody
    public Object string2hex(@RequestParam("string") String str,
                             @RequestParam("charset") String strCharset) throws Exception {

        try {
            JSONObject jsonOS = new JSONObject();
            String strRes = null;
            if (strCharset.equals("UTF-8")) {
                strRes = Convert.toHex(str, CharsetUtil.CHARSET_UTF_8);
            } else if (strCharset.equals("GBK")) {
                strRes =  Convert.toHex(str, CharsetUtil.CHARSET_GBK);
            } else if (strCharset.equals("ISO8859-1")) {
                strRes = Convert.toHex(str, CharsetUtil.CHARSET_ISO_8859_1);
            } else {
                String errMsg = String.format("当前请求的接口，不能识别【%s】字符集。", strCharset);
                return responseHelper.error(ErrorCodeEnum.ERROR_NO_SUCH_FUNC, errMsg);
            }
            jsonOS.put("hexString", strRes);
            jsonOS.put("size", strRes.length() / 2);

            return responseHelper.success(jsonOS);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

    @RequestMapping(value = "/hex2string")
    @ResponseBody
    public Object hex2string(@RequestParam("hex") String hexStr,
                             @RequestParam("charset") String strCharset) throws Exception {

        try {
            JSONObject jsonOS = new JSONObject();
            String strRes = null;
            if (strCharset.equals("UTF-8")) {
                strRes = Convert.hexToStr(hexStr, CharsetUtil.CHARSET_UTF_8);
            } else if (strCharset.equals("GBK")) {
                strRes = Convert.hexToStr(hexStr, CharsetUtil.CHARSET_GBK);
            } else if (strCharset.equals("ISO8859-1")) {
                strRes = Convert.hexToStr(hexStr, CharsetUtil.CHARSET_ISO_8859_1);
            } else {
                String errMsg = String.format("当前请求的接口，不能识别【%s】字符集。", strCharset);
                return responseHelper.error(ErrorCodeEnum.ERROR_NO_SUCH_FUNC, errMsg);
            }
            jsonOS.put("string",strRes);
            jsonOS.put("size", strRes.length());

            return responseHelper.success(jsonOS);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }
}
