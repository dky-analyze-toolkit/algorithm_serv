package com.toolkit.algorithm_serv.algorithm.auxtools;
import com.google.common.base.Preconditions;

import java.sql.Timestamp;
//import java.text.DateFormat;
//import java.text.SimpleDateFormat;
//import java.util.Date;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import static com.toolkit.algorithm_serv.utils.TimeUtils.parseTimeFromString;

public class TimeAuxUtils {

    public static String time2stamp(String timeStr) throws IllegalArgumentException {
//        Preconditions.checkArgument(randomLen >= 1 && randomLen <= 256, "指定的长度: %s 无效，取值范围应为1-256字节", randomLen);
        try {
            Timestamp createTime = parseTimeFromString(timeStr,"yyyy-mm-dd hh:mm:ss[. ...]");
            return createTime.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String stamp2time(String stampStr) throws IllegalArgumentException {
        try {
//            Timestamp createTime = timestamp(timeStr,"yyyy/MM/dd HH:mm:ss");
            String timeStr = "";

            return timeStr;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
