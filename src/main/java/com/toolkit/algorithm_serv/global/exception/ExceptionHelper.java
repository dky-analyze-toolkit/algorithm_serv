package com.toolkit.algorithm_serv.global.exception;

import cn.hutool.crypto.CryptoException;
import com.toolkit.algorithm_serv.global.bean.ResponseBean;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class ExceptionHelper {
    private final ResponseHelper responseHelper;

    @Autowired
    public ExceptionHelper(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }

    public ResponseBean response(Exception e) {
        e.printStackTrace();

        ErrorCodeEnum err;
        if (e instanceof IllegalArgumentException) {
            err = ErrorCodeEnum.ERROR_INVALID_ALG_PARAM;
        } else if (e instanceof CryptoException) {
            err = ErrorCodeEnum.ERROR_FAIL_CRYPT;
        } else {
            err = ErrorCodeEnum.ERROR_GENERAL_ERROR;
        }

        return responseHelper.error(err, e.getMessage());
    }
}
