package com.toolkit.algorithm_serv;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
// @ComponentScan({"com.toolkit.algorithm_serv.controller", "com.toolkit.algorithm_serv.global", "com.toolkit.algorithm_serv.global"})
// @ComponentScan({"com.toolkit"})
public class AlgorithmServApplication {

    public static void main(String[] args) {
        SpringApplication.run(AlgorithmServApplication.class, args);
    }

}
