package com.toolkit.algorithm_serv.services.sys_auth;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.io.IORuntimeException;
import cn.hutool.core.io.file.FileReader;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.core.util.HexUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.hmac.HMacHelper;
import com.toolkit.algorithm_serv.services.system.SystemManageHelper;
import com.toolkit.algorithm_serv.utils.FileUtils;
import com.toolkit.algorithm_serv.utils.TimeUtils;

public class SystemAuthHelper {
    private static byte[] mainKey = HexUtil.decodeHex("E31A1BCF2E9C8486");
    private static String sysAuthFilePath = FileUtils.joinPath(FileUtils.getWorkingPath(), "dat", "sa.dat");
    private static String sysAuthBackupFilePath = FileUtils.joinPath(FileUtils.getAppDataPath(), "dat", "sa.dat");

    public static String calcAuthCode(String fp) {
        // 对指纹计算hashmac，作为授权码
        byte[] result = HMacHelper.sha1hmac(fp, mainKey);
        return Base64.encodeUrlSafe(result);
    }

    public static String getEnvTodayFingerprint() {
        JSONObject jsonInfo = SystemManageHelper.getEnvHwInfo();
        jsonInfo.put("date", TimeUtils.asDay(DateUtil.date()));

        // 对硬件信息计算hashmac，作为当天动态指纹
        String hwInfo = jsonInfo.toJSONString();
        return Base64.encodeUrlSafe(HMacHelper.sha1hmac(hwInfo, mainKey));
    }

    public static boolean refreshSystemAuth(String authCode) {
        // 计算本机当天正确的授权码
        String todayFP = getEnvTodayFingerprint();
        String code = calcAuthCode(todayFP);

        // 校验待验证的授权码
        if (authCode.equals(code)) {
            // 授权码正确，则更新系统授权信息
            activateSystemAuth();
            return true;
        } else {
            return false;
        }
    }

    public static boolean checkSystemAuthStatus() {
        try {
            // 1. 读取授权数据
            String jsonStr = readSystemAuthRecord();
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

            // 更新上次系统访问的时间
            updateLastAccessDate();
            return true;
        } catch (Exception exception) {
            return false;
        }

    }

    private static void updateLastAccessDate() {
        try {
            String jsonStr = readSystemAuthRecord();
            JSONObject jsonAuth = (JSONObject) JSONObject.parse(jsonStr);

            DateTime authLast = DateUtil.parseDate(jsonAuth.getString("last"));
            DateTime nowTime = DateUtil.date();
            // 上次更新系统访问的时间，不是前一天及之前，则不作更新
            if (nowTime.isBefore(DateUtil.offsetDay(authLast, 1))) {
                return;
            }

            String nowTimeStr = TimeUtils.asDay(DateUtil.date());
            jsonAuth.put("last", nowTimeStr);
            String authFrom = jsonAuth.getString("auth_from");
            String authTo = jsonAuth.getString("expired");
            jsonAuth.put("mac", Base64.encode(HMacHelper.sha1hmac(authFrom + authTo + nowTimeStr, mainKey)));

            updateSystemAuthRecord(jsonAuth.toJSONString());
        } catch (Exception ex) {
            return;
        }
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

    private static void updateSystemAuthRecord(String authRecord) {
        FileWriter sysAuthFile = new FileWriter(sysAuthFilePath);
        sysAuthFile.write(authRecord);
        FileWriter sysAuthBackupFile = new FileWriter(sysAuthBackupFilePath);
        sysAuthBackupFile.write(authRecord);
    }

    private static String readSystemAuthRecord() {
        FileReader sysAuthFile = new FileReader(sysAuthFilePath);
        String authStr = sysAuthFile.readString();
        FileReader sysAuthBackupFile = new FileReader(sysAuthBackupFilePath);
        String authBackupStr = sysAuthBackupFile.readString();

        if (!authStr.equals(authBackupStr)) {
            return "";
        } else {
            return authStr;
        }
    }

    public static void activateSystemAuth() {
        String authRecord = initSysActivateRecord();
        updateSystemAuthRecord(authRecord);
    }
}
