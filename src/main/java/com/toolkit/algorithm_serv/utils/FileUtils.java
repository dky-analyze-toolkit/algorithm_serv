package com.toolkit.algorithm_serv.utils;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.PathUtil;
import cn.hutool.core.lang.UUID;
import cn.hutool.core.lang.generator.UUIDGenerator;
import cn.hutool.core.util.IdUtil;
import com.google.common.base.Strings;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Path;

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

    /**
     * 拼接目录或文件路径，不对当前目录'.'和上级目录'..'进行额外处理
     * @param params
     * @return
     */
    public static String joinPath(String... params) {
        String path = "";
        for (String param: params) {
            if (path.isEmpty()) {
                path = param;
            } else {
                path = path + File.separator + param;
            }
        }
        return path;
    }

    public static String getAppDataPath() {
        String appRoot;
        if (SystemUtils.isWindows()) {
            appRoot = System.getProperty("user.home");
        } else {
            appRoot = "/usr/local";
        }
        String appDataPath = joinPath(appRoot, "AppData", "tmp");

        File path = new File(appDataPath);
        if (!path.exists()) {
            path.mkdirs();
        }

        return appDataPath;
    }
}
