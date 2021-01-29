package com.toolkit.algorithm_serv.utils;

import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

public class FileUtils {

    /**
     * 获取工作目录
     *
     * @return 当前运行环境，本包的工作目录
     */
    public static String getWorkingPath() {
        String workingPath = System.getProperty("user.dir");
        System.out.println("user.dir : " + workingPath);
        return workingPath;
    }

    /**
     * 运行环境中，获取本包或本模块的类根目录，形如：
     * file:/home/ytwei/deploy/authapi/20181026/authapi-0.0.1-SNAPSHOT.jar!/BOOT-INF/classes!/
     * 或：/E:/Develop/IDEA%20Projects/AuthApi/target/classes/
     *
     * @return 包的根目录
     */
    public static String getClassRootPath() {
        String path = ClassUtils.getDefaultClassLoader().getResource("").getPath();
        try {
            path = URLDecoder.decode(path, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        // Windows平台需要把前缀斜杠除去
        if (SystemUtils.isWindows()) {
            path = StringUtils.trimLeadingCharacter(path, '/');
        }
        return path;
    }
}
