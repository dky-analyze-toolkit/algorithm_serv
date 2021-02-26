package com.toolkit.algorithm_serv.global.annotation;

import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SysAuth {
    String value() default "";
}
