package com.toolkit.algorithm_serv.services.pwd_crack;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.NumberUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.utils.SysAuxUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

public class JtrHelper {
    private static JSONObject cmdList = new JSONObject();
    static {
        cmdList.put("rar", "rar2john");
        cmdList.put("zip", "zip2john");
    }
    private static String johnPath() {
        return "modules/jtr/";
    }

    public static String getExtractCmd(String fileType) {
        boolean isWindows = SysAuxUtils.isWindows();
        String cmd = cmdList.getString(fileType);
        if (cmd == null) {
            // 按项目需要，临时用 rar 设置默认
            cmd = "rar2john";
        }
        return johnPath() + cmdList.getString(fileType);
    }

    public static String getJohnCmd() {
        return johnPath() + "john";
    }

    public static ArrayList<String> showHashCrack(String hashFilePath) throws IOException, InterruptedException {
        String[] args = new String[]{ getJohnCmd(), hashFilePath, "--show" };
        ArrayList<String> results = SysAuxUtils.execProc(args);
        return results;
    }

    private static int getCrackedNumber(ArrayList<String> results) {
        if (results.size() >= 3) {
            String[] infos = results.get(2).split(" ");
            return NumberUtil.parseInt(infos[0]);
        } else {
            return 0;
        }
    }

    private static String getCrackedPwd(ArrayList<String> results) {
        int crackNum = getCrackedNumber(results);
        if (crackNum > 0) {
            String[] infos = results.get(0).split(":");
            return infos[1];
        } else {
            return null;
        }
    }

    public static String getCrackedPwd(String hashFilePath) {
        try {
            ArrayList<String> results = showHashCrack(hashFilePath);
            return getCrackedPwd(results);
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String extractHash(String filePath) throws IOException, InterruptedException {
        File file = FileUtil.file(filePath);
        String fileType = FileUtil.getType(file);

        String cmd = getExtractCmd(fileType);
        String hashFilePath = filePath + ".hash";
        // String hashFilePath = "111.hash";
        // String[] args = new String[]{ cmd, filePath, ">", hashFilePath };
        String[] args = new String[]{ cmd, filePath };

        ArrayList<String> outputInfo = SysAuxUtils.execProc(args);
        FileUtil.writeUtf8Lines(outputInfo, hashFilePath);
        return hashFilePath;
    }

    public static Process crackHash(String hashFilePath) {
        String wordList = "--wordlist=" + johnPath() + "rockyou.txt";
        String[] args = new String[]{ getJohnCmd(), hashFilePath, wordList };
        return SysAuxUtils.execAndGetProc(args);
    }

    public static void stopCrack(Process crackProc) {
        if (crackProc == null) {
            return;
        }

        crackProc.destroyForcibly();
        // try {
            // BufferedWriter writer = SysAuxUtils.getProcWriter(crackProc);
            // writer.write("s");
            // writer.flush();
            // writer.close();
        // } catch (IOException e) {
        //     e.printStackTrace();
        // }
    }

}
