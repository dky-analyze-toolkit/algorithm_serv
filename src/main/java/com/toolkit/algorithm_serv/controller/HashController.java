package com.toolkit.algorithm_serv.controller;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.hash.HashHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


@RestController
@CrossOrigin(origins = "*",maxAge = 3600)
@RequestMapping(value = "/alg")
public class HashController {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public HashController(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    /**
     * 1.0 hash
     * 对原文计算摘要值，支持算法：MD5、SHA1、SHA256、SHA384、SHA512、SM3
     * alg: 参数指定hash算法（多个，用逗号分隔, 空值:计算全部）。单个接口返回所有指定的hash结果。
     * @return
     */
    @RequestMapping(value = "/hash", method = RequestMethod.GET)
    @ResponseBody
    public Object hash(@RequestParam("srchex") String srchex,
                       @RequestParam("alg") String alg) {

        try {
            JSONObject jsonOS = new JSONObject();
            alg = alg.toUpperCase();

            if (alg.contains("MD5")) {
                jsonOS.put("MD5", HashHelper.digest(srchex,"MD5"));
            }
            if (alg.contains("SHA1")) {
                jsonOS.put("SHA1", HashHelper.digest(srchex,"SHA1"));//SHA SHA1 SHA-1均为sha1
            }
            if (alg.contains("SHA256")) {
                jsonOS.put("SHA256", HashHelper.digest(srchex,"SHA-256"));
            }
            if (alg.contains("SHA384")) {
                jsonOS.put("SHA384", HashHelper.digest(srchex,"SHA-384"));
            }
            if (alg.contains("SHA512")) {
                jsonOS.put("SHA512", HashHelper.digest(srchex,"SHA-512"));
            }
            if (alg.contains("SM3")) {
                jsonOS.put("SM3", HashHelper.sm3(srchex));
            }

            if(alg.isEmpty())
            {
                jsonOS.put("MD5", HashHelper.digest(srchex,"MD5"));
                jsonOS.put("SHA1", HashHelper.digest(srchex,"SHA1"));
                jsonOS.put("SHA256", HashHelper.digest(srchex,"SHA-256"));
                jsonOS.put("SHA384", HashHelper.digest(srchex,"SHA-384"));
                jsonOS.put("SHA512", HashHelper.digest(srchex,"SHA-512"));
                jsonOS.put("SM3", HashHelper.sm3(srchex));
            }

            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException argEx) {
            return responseHelper.error(ErrorCodeEnum.ERROR_PARAM_LENGTH);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_SIGN);
        }
    }
}
