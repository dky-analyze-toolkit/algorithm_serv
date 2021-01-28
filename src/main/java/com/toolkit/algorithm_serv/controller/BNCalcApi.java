package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.rsa.RSAHelper;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils.BnAuxUtils;
import com.toolkit.algorithm_serv.utils.TimeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

@RestController
@RequestMapping(value = "/calc/bn")
public class BNCalcApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ExceptionHelper exceptionHelper;
    private final ResponseHelper responseHelper;

    @Autowired
    public BNCalcApi(ExceptionHelper exceptionHelper, ResponseHelper responseHelper) {
        this.exceptionHelper = exceptionHelper;
        this.responseHelper = responseHelper;
    }

    @PostMapping("/mod-pow")
    @ResponseBody
    public Object biModPow(
            @RequestParam("x_hex") String xHex,
            @RequestParam("y_hex") String yHex,
            @RequestParam("m_hex") String modulusHex
    ) {
        try {
            JSONObject jsonResult = BnAuxUtils.biPowModulus(xHex, yHex, modulusHex);
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/rsa-d")
    @ResponseBody
    public Object biRsaD(
            @RequestParam("p_hex") String pHex,
            @RequestParam("q_hex") String qHex,
            @RequestParam("e_hex") String eHex
    ) {
        try {
            JSONObject jsonResult = BnAuxUtils.biRsaD(pHex, qHex, eHex);
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/{operation}")
    @ResponseBody
    public Object biAdd(
            @PathVariable("operation") String operation,
            @RequestParam("x_hex") String xHex,
            @RequestParam("y_hex") String yHex
    ) {
        try {
            JSONObject jsonResult = BnAuxUtils.biCalc(operation, xHex, yHex);
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

}
