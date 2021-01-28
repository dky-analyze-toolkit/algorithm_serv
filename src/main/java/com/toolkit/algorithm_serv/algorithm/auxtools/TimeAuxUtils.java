package com.toolkit.algorithm_serv.algorithm.auxtools;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;

import java.sql.Timestamp;

public class TimeAuxUtils {

    public static String time2stamp(String timeStr) throws IllegalArgumentException {
        DateTime datetime = DateUtil.parse(timeStr);
        Long milliSeconds = Timestamp.valueOf(datetime.toString()).getTime();
        return milliSeconds.toString();
    }

    public static String stamp2time(String stampStr, String timeFormat) throws IllegalArgumentException {
        Timestamp timestamp = new Timestamp(0);
        timestamp.setTime(Long.valueOf(stampStr));
        return DateUtil.format(timestamp, timeFormat);
    }

}
