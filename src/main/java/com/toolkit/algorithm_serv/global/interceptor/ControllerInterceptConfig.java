package com.toolkit.algorithm_serv.global.interceptor;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;

@Configuration
public class ControllerInterceptConfig extends WebMvcConfigurationSupport {
    private final ControllerInterceptor controllerInterceptor;

    @Autowired
    public ControllerInterceptConfig(ControllerInterceptor controllerInterceptor) {
        this.controllerInterceptor = controllerInterceptor;
    }

    public void addSwaggerRegistry(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/**").addResourceLocations("classpath:/static/");
        registry.addResourceHandler("swagger-ui.html")
                .addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("doc.html")
                .addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/");
    }

    // 添加ResourceHandler
    // 添加Swagger资源的方法只能放在这个配置类里，放到swagger配置类里，访问 swagger-ui.html 会抛异常404
    // 放到 AuthapiApplication 中也会抛404
    // 原因未知
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        addSwaggerRegistry(registry);
        super.addResourceHandlers(registry);
    }

    /**
     * 针对异步的拦截器配置，拦截异步请求
     *
     * @param configurer
     */
    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        super.configureAsyncSupport(configurer);
        //比如如下给异步服务请求添加拦截器
        //configurer.registerCallableInterceptors((CallableProcessingInterceptor) timeInterceptor);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(controllerInterceptor);
    }

}
