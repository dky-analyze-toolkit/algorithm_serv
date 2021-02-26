package com.toolkit.algorithm_serv.global.aspect;

import com.toolkit.algorithm_serv.global.exception.ExceptionHelper;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.services.sys_auth.SystemAuthHelper;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
@SuppressWarnings({"unused"})
public class SysAuthAspect {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    public static final String TOKEN_KEY = "token";

    /**
     * checkUrl,keyUrl,tokenScope是通过Spring的@Value注解来获取配置文件中的配置项
     * @Value等同于Spring原先的配置模式中的value
     * <bean id="" class="">
     * 		<property name="" value="">
     * </bean>
     */
    // @Value(value = "${jwt.checkUrl}")
    // String checkUrl;
    //
    // @Value(value = "${jwt.keyUrl}")
    // String keyUrl;
    //
    // @Value(value = "${jwt.clientId}")
    // String tokenScope;

    @Pointcut("@annotation(com.toolkit.algorithm_serv.global.annotation.SysAuth)")
    public void annotationPointcut() {

    }

    @Pointcut("@within(com.toolkit.algorithm_serv.global.annotation.SysAuth)")
    public void withinPointcut() {

    }

    @Before("annotationPointcut()")
    public void beforePointcut(JoinPoint joinPoint) {
        // 此处进入到方法前  可以实现一些业务逻辑
    }

    @Around("withinPointcut()")
    public Object doClassAround(ProceedingJoinPoint joinPoint) throws Throwable {
        return doMethodAround(joinPoint);
    }

    @Around("annotationPointcut()")
    public Object doMethodAround(ProceedingJoinPoint joinPoint) throws Throwable {
        // MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        // String[] params = methodSignature.getParameterNames();// 获取参数名称
        // Object[] args = joinPoint.getArgs();// 获取参数值
        // if (null == params || params.length == 0){
        //     String mes = "Using Token annotation, the token parameter is not passed, and the parameter is not valid.";
        //     logger.info(mes);
        //     throw new Exception(mes);
        // }
        // boolean hasToken = false;
        // int index = 0;
        // for (int i = 0; i < params.length; i++) {
        //     if (TOKEN_KEY.equals(params[i])) {
        //         hasToken = true;
        //         index = i;
        //         break;
        //     }
        // }
        // if (!hasToken){
        //     String mes = "The token parameter is not included in the requested parameter, the parameter is not valid.";
        //     logger.info(mes);
        //     throw new Exception(mes);
        // }
        try {
            this.checkSystemAuthStatus();
        } catch (Exception e) {
            ResponseHelper responseHelper = new ResponseHelper();
            ExceptionHelper exceptionHelper = new ExceptionHelper(responseHelper);
            return exceptionHelper.response(e);
        }
        return joinPoint.proceed();
    }

    /**
     * 在切入点return内容之后切入内容（可以用来对处理返回值做一些加工处理）
     * @param joinPoint
     */
    @AfterReturning("annotationPointcut()")
    public void doAfterReturning(JoinPoint joinPoint) {
    }

    private void checkSystemAuthStatus() throws Exception {
        if (!SystemAuthHelper.checkSystemAuthStatus()) {
            throw new IllegalAccessException("系统未授权，或授权过期，请使用有效授权码激活系统。");
        }
    }

    // private void checkToken(String token) {
    //     Decrypt decrypt = new Decrypt();// 这个类是自己的业务类，主要进行token验证(JWT)
    //     try {
    //         decrypt.check(token, checkUrl, keyUrl, tokenScope);
    //     } catch (Exception e) {
    //         logger.info(e.getMessage());
    //         throw new RuntimeException(e.getMessage());
    //     }
    // }
}
