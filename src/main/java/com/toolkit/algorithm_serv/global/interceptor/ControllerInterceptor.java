package com.toolkit.algorithm_serv.global.interceptor;


import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@Component
public class ControllerInterceptor implements HandlerInterceptor {
    private org.slf4j.Logger logger = LoggerFactory.getLogger(ControllerInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (handler instanceof HandlerMethod) {
            // 获取类名
            String className = ((HandlerMethod) handler).getBean().getClass().getName();
            // 获取方法名
            String methodName = ((HandlerMethod) handler).getMethod().getName();
            // 会话id和用户名
            String sessionId = request.getSession().getId();

            // 记录调用方法名
            logger.info("---PreHandle---:" + "\tMethod: " + methodName +
                    "\tsessionId: " + sessionId);

            // 记录调用接口参数
            Map<String, String[]> paramsMap = request.getParameterMap();
            String paramsInfo = "";
            for (String key : paramsMap.keySet()) {
                String[] values = paramsMap.get(key);
                paramsInfo += String.format("%s: %s; ", key, values[0]);
            }
            logger.info(paramsInfo);

            // 提取接口参数中的 access_token ，保存到 session 中
            // if (paramsMap.containsKey(MyConst.ACCESS_TOKEN)) {
            //     String accessToken = paramsMap.get(MyConst.ACCESS_TOKEN)[0];
            //     Object attrObj = request.getSession().getAttribute(MyConst.ACCESS_TOKEN);
            //     // 会话中没有 token ，或者会话中保存的 token 和本次校验通过的不同，则保存新的 token
            //     // 进入 preHandle 前，已经校验完 token
            //     if (attrObj == null || !accessToken.equals((String)attrObj)) {
            //         request.getSession().setAttribute(MyConst.ACCESS_TOKEN, accessToken);
            //     }
            // }

//            String exceptionName = ((HandlerMethod) handler).getMethod().getExceptionTypes().getClass().getName();
//            logger.info(exceptionName);
        } else {

        }

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object obj, ModelAndView modelAndView) throws Exception {
        if (obj instanceof HandlerMethod) {
            // 获取类名
            String className = ((HandlerMethod) obj).getBean().getClass().getName();
            // 获取方法名
            String methodName = ((HandlerMethod) obj).getMethod().getName();
//            logger.info("---PostHandle---:" + "\tClass: " + className + "\tMethod: " + methodName);
            logger.info("---PostHandle---:" + "\tMethod: " + methodName);
        } else {

        }

    }

}
