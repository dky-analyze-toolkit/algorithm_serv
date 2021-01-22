package com.toolkit.algorithm_serv.algorithm.auxtools;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
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
        try {

            DateTime datetime = DateUtil.parse(timeStr);

            Timestamp timestamp = parseTimeFromString(timeStr, "yyyy-mm-dd hh:mm:ss");
            Long milliSeconds = timestamp.getTime();
//            timestamp.setTime(milliSeconds);
            return milliSeconds.toString();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String stamp2time(String stampStr) throws IllegalArgumentException {
        try {
            Timestamp timestamp = new Timestamp(0);
            timestamp.setTime(Long.valueOf(stampStr));
            return timestamp.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
