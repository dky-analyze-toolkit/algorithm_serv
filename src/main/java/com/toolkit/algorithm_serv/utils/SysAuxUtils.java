package com.toolkit.algorithm_serv.utils;

import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.ArrayList;
import java.util.Properties;

public class SysAuxUtils {
    protected static Logger logger = LoggerFactory.getLogger(SysAuxUtils.class);
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

    /**
     * 获取从给定进程读取输出信息的 reader，进程输出相当于系统输入，用 InputStreamReader
     * @param proc 进程实例
     * @return BufferedReader，使用后要显式关闭，reader.close()
     * @throws IOException
     */
    public static BufferedReader getProcReader(Process proc) throws IOException {
        // 中文版 Windows 运行时环境的输出默认是 GBK 编码
//        return new BufferedReader(new InputStreamReader(proc.getInputStream(), "GBK"));
        return new BufferedReader(new InputStreamReader(proc.getInputStream(), SysAuxUtils.getEnvEncoding()));
    }

    /**
     * 获取可向给定进程输入数据的 writer，进程输入相当于系统输出，用 OutputStreamWriter
     * @param proc 进程实例
     * @return BufferedWriter，使用后要显式关闭，writer.close()
     * @throws IOException
     */
    public static BufferedWriter getProcWriter(Process proc) throws IOException {
        // 中文版 Windows 运行时环境的输出默认是 GBK 编码
        return new BufferedWriter(new OutputStreamWriter(proc.getOutputStream(), SysAuxUtils.getEnvEncoding()));
    }

    /**
     * 获取给定进程错误信息的 reader
     * @param proc 进程实例
     * @return BufferedReader，使用后要显式关闭，reader.close()
     * @throws IOException
     */
    public static BufferedReader getProcError(Process proc) throws IOException {
        // 中文版 Windows 运行时环境的输出默认是 GBK 编码
        return new BufferedReader(new InputStreamReader(proc.getErrorStream(), SysAuxUtils.getEnvEncoding()));
    }

    /**
     * Deprecated 名称有歧义，改成使用 execReader
     * @param args 命令行执行的参数
     * @return BufferedReader，使用后要显式关闭，reader.close()
     * @throws IOException
     */
    public static BufferedReader getExecInStream(String[] args) throws IOException {
        Process proc = Runtime.getRuntime().exec(args);
        return getProcReader(proc);
    }

    /**
     * 执行命令行语句，并返回输出结果的 reader
     * @param args 命令行语句的参数
     * @return BufferedReader，使用后要显式关闭，reader.close()
     * @throws IOException
     */
    public static BufferedReader execReader(String[] args) throws IOException {
        Process proc = Runtime.getRuntime().exec(args);
        return getProcReader(proc);
    }

    /**
     * 执行命令行语句，并返回执行的输出结果
     * @param args 命令行语句的参数
     * @return 执行结果
     * @throws InterruptedException
     * @throws IOException
     */
    public static ArrayList<String> execProc(String[] args) throws InterruptedException, IOException {
        Process proc = Runtime.getRuntime().exec(args);
        BufferedReader reader = SysAuxUtils.getProcReader(proc);
        String line;
        ArrayList<String> results = new ArrayList<String>();
        while ((line = reader.readLine()) != null) {
            logger.info(line);
            results.add(line);
        }
        reader.close();

        int exitVal = proc.waitFor();
        System.out.println("Exited with error code: " + exitVal + ". Thread is: " + Thread.currentThread().getName());
        return results;
    }

    public static Process execAndGetProc(String[] args) {
        Process proc = null;
        try {
            proc = Runtime.getRuntime().exec(args);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return proc;
    }


    public static boolean checkServiceActive(String service) {
        try {
            String command = String.format("systemctl status %s | grep Active", service);
            String[] args = new String[] { "sh", "-c", command };
            BufferedReader output = execReader(args);

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
