package com.toolkit.algorithm_serv.global.exception;

import cn.hutool.crypto.CryptoException;
import com.toolkit.algorithm_serv.global.bean.ResponseBean;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

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
        if (e instanceof IllegalArgumentException || e instanceof InvalidAlgorithmParameterException) {
            err = ErrorCodeEnum.ERROR_INVALID_ALG_PARAM;
        } else if (e instanceof CryptoException) {
            err = ErrorCodeEnum.ERROR_FAIL_CRYPT;
        } else if (e instanceof NoSuchAlgorithmException) {
            err = ErrorCodeEnum.ERROR_ALG_NOT_SUPPORT;
        } else if (e instanceof BadPaddingException) {
            err = ErrorCodeEnum.ERROR_BAD_PADDING;
        } else if (e instanceof NoSuchPaddingException) {
            err = ErrorCodeEnum.ERROR_NO_SUCH_PADDING;
        } else if (e instanceof IllegalBlockSizeException) {
            err = ErrorCodeEnum.ERROR_BAD_BLOCK_SIZE;
        } else if (e instanceof InvalidKeyException || e instanceof InvalidKeySpecException) {
            err = ErrorCodeEnum.ERROR_BAD_CRYPT_KEY;
        } else {
            err = ErrorCodeEnum.ERROR_GENERAL_ERROR;
        }

        return responseHelper.error(err, e.getMessage());
    }
}
