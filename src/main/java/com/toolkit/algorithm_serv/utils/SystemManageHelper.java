package com.toolkit.algorithm_serv.utils;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IORuntimeException;
import cn.hutool.core.io.file.FileReader;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.core.io.file.PathUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.HMac;
import cn.hutool.crypto.digest.HmacAlgorithm;
import cn.hutool.system.oshi.OshiUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.hmac.HMacHelper;
import oshi.hardware.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;

public class SystemManageHelper {
    private static byte[] mainKey = HexUtil.decodeHex("E31A1BCF2E9C8486");
    private static String sysAuthFilePath = FileUtils.getWorkingPath() + "/dat/sa.dat";

    public static JSONObject getEnvHwInfo() {
        JSONObject jsonInfo = new JSONObject();

        ComputerSystem computerSystem = OshiUtil.getHardware().getComputerSystem();
        String computerSystemSN = computerSystem.getSerialNumber();
        jsonInfo.put("computerSystemSN", computerSystemSN);

        Baseboard baseboard = computerSystem.getBaseboard();
        String baseboardSN = baseboard.getSerialNumber();
        jsonInfo.put("baseboardSN", baseboardSN);

        CentralProcessor centralProcessor = OshiUtil.getProcessor();
        String cpuID = centralProcessor.getIdentifier();
        jsonInfo.put("cpuID", cpuID);

        // HardwareAbstractionLayer hardware = OshiUtil.getHardware();
        // HWDiskStore[] disks = hardware.getDiskStores();
        // String diskSN = disks[0].getSerial();
        // jsonInfo.put("diskSN", diskSN);
        //
        // List<NetworkIF> netIFs = OshiUtil.getNetworkIFs();
        // String netCardMac = netIFs.get(0).getMacaddr();
        // jsonInfo.put("netCardMac", netCardMac);

        return jsonInfo;
    }

    public static String getEnvTodayFingerprint() {
        JSONObject jsonInfo = getEnvHwInfo();
        jsonInfo.put("date", TimeUtils.asDay(DateUtil.date()));

        String hwInfo = jsonInfo.toJSONString();

        byte[] result = HMacHelper.sha1hmac(hwInfo, mainKey);

        return Base64.encode(result);
    }

    public static String calcAuthCode(String fp) {
        byte[] result = HMacHelper.sha1hmac(fp, mainKey);
        return Base64.encode(result);
    }

    public static boolean refreshSystemAuth(String authCode) {
        String todayFP = getEnvTodayFingerprint();
        String code = calcAuthCode(todayFP);
        if (authCode.equals(code)) {
            activateSystemAuth();
            return true;
        } else {
            return false;
        }
    }

    public static boolean checkSystemAuthStatus() {
        try {
            // 1. 打开授权文件并读取授权数据（同时检查授权文件是否存在）
            FileReader sysAuthFile = new FileReader(sysAuthFilePath);
            String jsonStr = sysAuthFile.readString();
            JSONObject jsonAuth = (JSONObject) JSONObject.parse(jsonStr);

            String authFrom = jsonAuth.getString("auth_from");
            String authTo = jsonAuth.getString("expired");
            String authLast = jsonAuth.getString("last");
            DateTime dateFrom = DateUtil.parseDate(authFrom);
            DateTime dateExpired = DateUtil.parseDate(authTo);
            DateTime dateLast = DateUtil.parseDate(authLast);
            DateTime now = DateUtil.date();

            String mac = jsonAuth.getString("mac");
            byte[] expectedMac = HMacHelper.sha1hmac(authFrom + authTo + authLast, mainKey);

            if (!mac.equals(Base64.encode(expectedMac))) {
                // 2. 检查验证码
                return false;
            } else if (now.isAfter(dateExpired) || now.isBefore(dateFrom)) {
                // 3. 检查起始时间和到期时间
                return false;
            } else if (now.isBefore(dateLast)) {
                // 4. 上次操作时间的比较
                return false;
            }

            // TODO: 优化成每天一次更新，和启动时更新
            updateLastAccessDate(jsonAuth);
            return true;
        } catch (IORuntimeException exception) {
            return false;
        }

    }

    private static void updateLastAccessDate(JSONObject jsonAuth) {
        DateTime today = DateUtil.date();
        String authFrom = jsonAuth.getString("auth_from");
        String authTo = jsonAuth.getString("expired");
        String authLast = TimeUtils.asDay(today);
        jsonAuth.put("last", authLast);
        jsonAuth.put("mac", Base64.encode(HMacHelper.sha1hmac(authFrom + authTo + authLast, mainKey)));

        FileWriter sysAuthFile = new FileWriter(sysAuthFilePath);
        sysAuthFile.write(jsonAuth.toJSONString());
    }

    private static String initSysActivateRecord() {
        DateTime today = DateUtil.date();
        DateTime expiredDate = DateUtil.offsetMonth(today, 6);

        JSONObject jsonAuth = new JSONObject();
        String authFrom = TimeUtils.asDay(today);
        String authTo = TimeUtils.asDay(expiredDate);
        jsonAuth.put("auth_from", authFrom);
        jsonAuth.put("expired", authTo);
        jsonAuth.put("last", authFrom);
        jsonAuth.put("mac", Base64.encode(HMacHelper.sha1hmac(authFrom + authTo + authFrom, mainKey)));

        return jsonAuth.toJSONString();
    }

    public static void activateSystemAuth() {

        FileWriter sysAuthFile = new FileWriter(sysAuthFilePath);
        sysAuthFile.write(initSysActivateRecord());
    }
}
