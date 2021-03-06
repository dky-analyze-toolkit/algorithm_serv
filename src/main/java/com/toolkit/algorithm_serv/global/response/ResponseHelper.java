package com.toolkit.algorithm_serv.global.response;

import com.toolkit.algorithm_serv.global.bean.ResponseBean;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.utils.TimeUtils;
import org.springframework.stereotype.Component;

@Component
public class ResponseHelper {
    public ResponseBean error(ErrorCodeEnum err) {
        return  error(err, null);
    }

    public ResponseBean error(ErrorCodeEnum err, Object data) {
        ResponseBean responseBean = new ResponseBean();
        responseBean.setCode(err.getCode());
        responseBean.setError(err.getMsg());
        responseBean.setTimeStamp(TimeUtils.getCurrentSystemTimestamp());
        responseBean.setPayload(data);
        return responseBean;
    }

    public ResponseBean success() {
        return success(null);
    }

    public ResponseBean success(Object data) {
        return error(ErrorCodeEnum.ERROR_OK, data);
    }

    public boolean isSuccess(ResponseBean response) {
        if ( response.getCode() == ErrorCodeEnum.ERROR_OK.getCode())
            return true;
        else
            return false;
    }
}
