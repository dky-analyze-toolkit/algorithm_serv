package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.convert.Convert;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import cn.hutool.core.io.resource.ResourceUtil;
import cn.hutool.core.net.URLDecoder;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.PemUtil;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.http.HttpUtil;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Strings;
import com.toolkit.algorithm_serv.algorithm.b64.Base64Coding;
import com.toolkit.algorithm_serv.algorithm.rsa.RSAHelper;
import com.toolkit.algorithm_serv.algorithm.sym_crypt.SymCryptHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static cn.hutool.crypto.PemUtil.readPemObject;
import static com.toolkit.algorithm_serv.algorithm.auxtools.TimeAuxUtils.stamp2time;
import static com.toolkit.algorithm_serv.algorithm.auxtools.TimeAuxUtils.time2stamp;
import static com.toolkit.algorithm_serv.algorithm.rsa.RSAHelper.toPem;
import static com.toolkit.algorithm_serv.algorithm.rsa.RSAHelper.readPem;

@RestController
@RequestMapping(value = "/transcoding")
public class TransCodingApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ExceptionHelper exceptionHelper;
    private final ResponseHelper responseHelper;

    @Autowired
    public TransCodingApi(ExceptionHelper exceptionHelper, ResponseHelper responseHelper) {
        this.exceptionHelper = exceptionHelper;
        this.responseHelper = responseHelper;
    }

    private void putHexSize(JSONObject jsonResult, String hex) {
        jsonResult.put("size", hex.length() / 2);
        jsonResult.put("bits", hex.length() / 2 * 8);
    }

    private void jsonPutHex(JSONObject jsonResult, String key, String value) {
        jsonResult.put(key + "_hex", value);
        jsonResult.put(key + "_b64", Base64.encode(value));
        putHexSize(jsonResult, value);
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
            @RequestParam(value = "time_str", required = false) String timeStr,
            @RequestParam(value = "time_stamp", required = false) String stampStr,
            @RequestParam(value = "time_format", required = false) String timeFormat) {
        try {
            JSONObject jsonRes = new JSONObject();
            if (codeAct.equalsIgnoreCase("str2timestamp")) {
                if (StrAuxUtils.isValid(timeStr)) {
                    stampStr = time2stamp(timeStr);
                }
                jsonRes.put("time_stamp", stampStr);
                return responseHelper.success(jsonRes);
            } else if (codeAct.equalsIgnoreCase("timestamp2str")) {
                if (StrAuxUtils.isValid(stampStr)) {
                    timeStr = stamp2time(stampStr, timeFormat);
                }
                jsonRes.put("time_str", timeStr);
                return responseHelper.success(jsonRes);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_TIME_CONVERT, "不能识别的参数，arg：" + codeAct);
            }
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }

    }

    @RequestMapping(value = "/string2hex")
    @ResponseBody
    public Object string2hex(@RequestParam("plain_str") String str,
                             @RequestParam("charset") String strCharset) throws Exception {

        try {
            JSONObject jsonOS = new JSONObject();
            String strRes = null;
            if (strCharset.equals("UTF-8")) {
                strRes = Convert.toHex(str, CharsetUtil.CHARSET_UTF_8);
            } else if (strCharset.equals("GBK")) {
                strRes = Convert.toHex(str, CharsetUtil.CHARSET_GBK);
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
    public Object hex2string(@RequestParam("plain_hex") String hexStr,
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
            jsonOS.put("string", strRes);
            jsonOS.put("size", strRes.length());

            return responseHelper.success(jsonOS);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

    @PostMapping("/url/{arg}")
    @ResponseBody
    public Object urlCode(
            @PathVariable(value = "arg", required = true) String codeAct,
            @RequestParam(value = "plain_str", required = false) String plainStr,
            @RequestParam(value = "code_str", required = false) String codeStr
    ) {
        try {
            if (codeAct.equalsIgnoreCase("encode")) {
                String encodeText = "";
                if (StrAuxUtils.isValid(plainStr)) {
                    encodeText = HttpUtil.encodeParams(plainStr, CharsetUtil.CHARSET_UTF_8);
                } else {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PARAMETER, "编码时需要填入参数 plain_hex 。");
                }
                JSONObject jsonRes = new JSONObject();
                jsonRes.put("encode_str", encodeText);
                jsonRes.put("length", encodeText.length());
                return responseHelper.success(jsonRes);
            } else if (codeAct.equalsIgnoreCase("decode")) {
                if (StrAuxUtils.isValid(codeStr)) {
                    String decodeStr = URLDecoder.decode(codeStr, CharsetUtil.CHARSET_UTF_8);

                    JSONObject jsonRes = new JSONObject();
                    jsonRes.put("decode_str", decodeStr);
                    jsonRes.put("size", decodeStr.length());
                    return responseHelper.success(jsonRes);
                } else {
                    return responseHelper.error(ErrorCodeEnum.ERROR_NEED_PARAMETER, "解码时需要填入参数 code_str 。");
                }
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_INVALID_URL, "只支持 base64 编码和解码，不支持：" + codeAct + "。");
            }
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }

    }

    @PostMapping("/pem2hex")
    @ResponseBody
    public Object pem2hex(@RequestParam(value = "pem") String pemStr) {
        try {
            JSONObject jsonResult = new JSONObject();

            InputStream pemStream = IoUtil.toStream(pemStr, CharsetUtil.CHARSET_UTF_8);
            PemObject pemObject = readPemObject(pemStream);
            if (null != pemObject) {
//                jsonPutHex(jsonResult, "hexString", StrAuxUtils.bytesToHexString(pemObject.getContent()));
//                putHexSize(jsonResult, StrAuxUtils.bytesToHexString(pemObject.getContent()));
                jsonResult.put("pem_hex", StrAuxUtils.bytesToHexString(pemObject.getContent()));
            }

            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/hex2pem")
    @ResponseBody
    public Object hex2pem(@RequestParam(value = "hex") String plainHex,
                          @RequestParam(value = "type") String typeStr) {
        try {
            JSONObject jsonResult = new JSONObject();
            byte[] bytePem = StrAuxUtils.hexStringToBytes(plainHex);

            if (typeStr.equals("publicKey")) {
                jsonResult.put("pem", toPem("PUBLIC KEY", bytePem));
            } else if (typeStr.equals("privateKey")) {
                jsonResult.put("pem", toPem("PRIVATE KEY", bytePem));
            } else if (typeStr.equals("privateKey")) {
                jsonResult.put("pem", toPem("CERTIFICATE", bytePem));
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_TYPE_PEM, "不支持的数据类型：" + typeStr + "。");
            }

            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/pem-parse")
    @ResponseBody
    public Object pemParse(@RequestParam(value = "pem") String pemStr) {
        try {
            JSONObject jsonResult = new JSONObject();
            jsonResult = readPem(pemStr);
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/generate-pem")
    @ResponseBody
    public Object generatePem(@RequestParam(value = "rsa_p_hex") String pHex,
                              @RequestParam(value = "rsa_q_hex") String qHex,
                              @RequestParam(value = "rsa_e_hex") String eHex) {
        try {
            JSONObject jsonResult = new JSONObject();

            BigInteger biP = new BigInteger(pHex, 16);
            BigInteger biQ = new BigInteger(qHex, 16);
            BigInteger biE = new BigInteger(eHex, 16);
            BigInteger biOne = new BigInteger("1");
            BigInteger biModulus = biP.subtract(biOne).multiply(biQ.subtract(biOne));
            BigInteger biN = biP.multiply(biQ);
            BigInteger biD = biE.modInverse(biModulus);
            BigInteger biDP = biD.mod(biP.subtract(BigInteger.ONE));
            BigInteger biDQ = biD.mod(biQ.subtract(BigInteger.ONE));
            BigInteger biQInv = biQ.modInverse(biP);

            /**
             *  3. 创建 RSA私钥
             * */
//            public static final String KEY_ALGORITHM_MODE_PADDING = "RSA/ECB/NoPadding"; //不填充
//            public static final String KEY_ALGORITHM = "RSA"; //不填充

//            RSAPrivateCrtKeyParameters parameters = new RSAPrivateCrtKeyParameters(biN, biE, biD, biP, biQ, biDP, biDQ, biQInv);
//            BCRSAPrivateCrtKey keyspec1 = new BCRSAPrivateCrtKey(parameters);

            RSAPrivateKeySpec keyspec = new RSAPrivateKeySpec(biN, biD);
            RSAPublicKeySpec keypub = new RSAPublicKeySpec(biN, biD);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");//KEY_ALGORITHM);
            Key privateKey = keyFactory.generatePrivate(keyspec);
            Key publicKey = keyFactory.generatePublic(keypub);

            jsonResult.put("public_key_pem", toPem("PUBLIC KEY", publicKey.getEncoded()));
            jsonResult.put("private_key_pem", toPem("PRIVATE KEY", privateKey.getEncoded()));

            return responseHelper.success(jsonResult);
        } catch (Exception msg) {
            return exceptionHelper.response(msg);
        }
    }
}
