package com.toolkit.algorithm_serv.global.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class SystemExceptionHandler {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());
    private final ExceptionHelper exceptionHelper;

    @Autowired
    public SystemExceptionHandler(ExceptionHelper exceptionHelper) {
        this.exceptionHelper = exceptionHelper;
    }

    @ExceptionHandler(value = Exception.class)
    public Object handleException(HttpServletRequest request, Exception e) {
        // 获取方法名
        String methodName = request.getMethod();
        // 接口路径
        String uriPath = request.getRequestURI();

        // 记录异常信息
        logger.info("--- Exception ---:" + "\t" + methodName + "\t" + uriPath);

        return exceptionHelper.response(e);
    }
}
