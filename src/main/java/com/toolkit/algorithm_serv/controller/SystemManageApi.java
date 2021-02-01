package com.toolkit.algorithm_serv.controller;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.services.sys_auth.SystemAuthHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/system/manage")
public class SystemManageApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ExceptionHelper exceptionHelper;
    private final ResponseHelper responseHelper;

    @Autowired
    public SystemManageApi(ExceptionHelper exceptionHelper, ResponseHelper responseHelper) {
        this.exceptionHelper = exceptionHelper;
        this.responseHelper = responseHelper;
    }

    @GetMapping("/env-fingerprint")
    @ResponseBody
    public Object getEnvFingerprint() {
        try {
            JSONObject jsonResult = new JSONObject();
            jsonResult.put("env_fp", SystemAuthHelper.getEnvTodayFingerprint());
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/calc-auth-code")
    @ResponseBody
    public Object calculateAuthCode(
            @RequestParam("today_fp") String todayFP
    ) {
        try {
            JSONObject jsonResult = new JSONObject();
            jsonResult.put("auth_code", SystemAuthHelper.calcAuthCode(todayFP));
            return responseHelper.success(jsonResult);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

    @PostMapping("/authorize")
    @ResponseBody
    public Object refreshAuthorize(
            @RequestParam("auth_code") String authCode
    ) {
        try {
            boolean result = SystemAuthHelper.refreshSystemAuth(authCode);
            return responseHelper.success(result);
        } catch (Exception e) {
            return exceptionHelper.response(e);
        }
    }

}
