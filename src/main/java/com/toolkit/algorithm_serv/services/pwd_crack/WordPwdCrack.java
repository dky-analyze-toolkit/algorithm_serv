package com.toolkit.algorithm_serv.services.pwd_crack;

import cn.hutool.core.io.FileUtil;
import com.sun.jna.StringArray;
import com.toolkit.algorithm_serv.global.exception.UnlockPasswordExcept;
import com.toolkit.algorithm_serv.utils.FileUtils;
import com.toolkit.algorithm_serv.utils.SysAuxUtils;
import com.toolkit.algorithm_serv.utils.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class WordPwdCrack {
    protected static Logger logger = LoggerFactory.getLogger(WordPwdCrack.class);

    public static String crackFile(String filePath) {
        try {
            String[] args1 = new String[]{"modules/craXcel-cli/craxcel.py", filePath};
            ArrayList<String> results = WordPwdCrack.runPython(args1);
            for (String line: results) {
                if (line.startsWith("cracked_file:")) {
                    String unlocked_path = line.substring(13);
                    return unlocked_path;
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
            throw new UnlockPasswordExcept("文件读写异常");
        } catch (InterruptedException e) {
            e.printStackTrace();
            throw new UnlockPasswordExcept("口令破解进程异常终止");
        }

        throw new UnlockPasswordExcept("破解进程未成功破解口令");
    }

    public static byte[] readUnlockedFileData(String filePath) {
        byte[] data = FileUtil.readBytes(filePath);
        return data;
    }

    public static ArrayList<String> runPython(String[] args) throws InterruptedException, IOException {
        boolean isWindows = SystemUtils.isWindows();
        String pythonCmd = isWindows ? "python" : "python3";

        ArrayList<String> py_args = new ArrayList<String>(Arrays.asList(args));
        py_args.add(0, pythonCmd);
        args = py_args.toArray(args);

        return SystemUtils.execProc(args);
    }

    // public static ArrayList<String> runPython(String[] args) throws InterruptedException, IOException {
    //     boolean isWindows = SystemUtils.isWindows();
    //     String pythonCmd = isWindows ? "python" : "python3";
    //
    //     ArrayList<String> py_args = new ArrayList<String>(Arrays.asList(args));
    //     py_args.add(0, pythonCmd);
    //     args = py_args.toArray(args);
    //
    //     Process proc = Runtime.getRuntime().exec(args);
    //     BufferedReader output = SysAuxUtils.getProcReader(proc);
    //     String line;
    //     ArrayList<String> results = new ArrayList<String>();
    //     while ((line = output.readLine()) != null) {
    //         logger.info(line);
    //         results.add(line);
    //     }
    //     output.close();
    //
    //     int exitVal = proc.waitFor();
    //     System.out.println("Exited with error code: " + exitVal + ". Thread is: " + Thread.currentThread().getName());
    //     return results;
    // }

}
