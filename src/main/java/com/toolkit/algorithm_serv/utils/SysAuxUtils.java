package com.toolkit.algorithm_serv.utils;

import com.alibaba.fastjson.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;

public class SysAuxUtils {
    public static Properties sysProps = System.getProperties();

    static public String getOsName() {
        return sysProps.getProperty("os.name");
    }

    static public String getOsArch() {
        return sysProps.getProperty("os.arch");
    }

    static public String getOsVersion() {
        return sysProps.getProperty("os.version");
    }

    static public boolean isWindows() {
        String osName = getOsName();
        return osName.indexOf("Windows") >= 0;
    }

    static public String getProp(String propName) {
        return sysProps.getProperty(propName);
    }

    static public JSONObject getProps() {
        String[] keys = {
                "os.name", "sun.boot.library.path", "user.dir", "user.country", "java.runtime.version",
                "os.arch", "line.separator", "os.version", "user.home", "user.timezone", "user.name",
                "user.language", "file.separator",
                "java.specification.version", "java.home", "sun.arch.data.model", "awt.toolkit",
                "sun.jnu.encoding", "java.vm.version", "java.library.path", "java.class.version",
                "java.runtime.name", "java.vm.vendor", "file.encoding", "java.version", "java.vendor",
                "java.vm.name", "sun.os.patch.level", "PID", "catalina.base", "sun.cpu.endian",
                "java.awt.graphicsenv", "java.endorsed.dirs", "java.io.tmpdir", "sun.desktop"
        };
        JSONObject props = new JSONObject();

        for (String key: keys) {
            props.put(key, sysProps.getProperty(key));
        }
        return props;
    }

    static public String getEnvEncoding() {
        return sysProps.getProperty("sun.jnu.encoding");
    }

    public static BufferedReader getProcReader(Process proc) throws IOException {
        // 中文版 Windows 运行时环境的输出默认是 GBK 编码
//        return new BufferedReader(new InputStreamReader(proc.getInputStream(), "GBK"));
        return new BufferedReader(new InputStreamReader(proc.getInputStream(), SysAuxUtils.getEnvEncoding()));
    }

    public static BufferedReader getExecOutput(String[] args) throws IOException {
        Process proc = Runtime.getRuntime().exec(args);
        return getProcReader(proc);
    }

    public static boolean checkServiceActive(String service) {
        try {
            String command = String.format("systemctl status %s | grep Active", service);
            String[] args = new String[] { "sh", "-c", command };
            BufferedReader output = getExecOutput(args);

            String line = output.readLine();
            output.close();
            if (line == null || line.isEmpty()) {
                return false;
            } else {
                return line.contains("Active: active");
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

}
