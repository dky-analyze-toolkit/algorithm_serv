package com.toolkit.algorithm_serv.controller;

import com.toolkit.algorithm_serv.global.annotation.*;
import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.exception.SizeMismatchExcept;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@SysAuth
@RequestMapping(value = "/crack-pwd")
public class CrackPwdApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ExceptionHelper exceptionHelper;
    private final ResponseHelper responseHelper;

    @Autowired
    public CrackPwdApi(ExceptionHelper exceptionHelper, ResponseHelper responseHelper) {
        this.exceptionHelper = exceptionHelper;
        this.responseHelper = responseHelper;
    }

    @PostMapping("/word/remove-pwd")
    @ResponseBody
    public Object removeWordPwd(
            @RequestParam("file_item") MultipartFile wordFile
    ) {
        throw new SizeMismatchExcept("test");
        // try {
        //     throw new SizeMismatchExcept("test");
        //     // return responseHelper.success("OK");
        // } catch (Exception e) {
        //     return exceptionHelper.response(e);
        // }
    }

}
