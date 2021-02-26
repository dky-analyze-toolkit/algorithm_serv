package com.toolkit.algorithm_serv.algorithm.auxtools;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.StrUtil;

import java.sql.Timestamp;

public class TimeAuxUtils {

    public static String time2stamp(String timeStr) throws IllegalArgumentException {
        DateTime datetime = DateUtil.parse(timeStr);
        Long seconds = Timestamp.valueOf(datetime.toString()).getTime() / 1000;
        return String.valueOf(seconds);
    }

    public static String stamp2time(String stampStr, String timeFormat) throws IllegalArgumentException {
        Long milliSeconds = Long.valueOf(stampStr) * 1000;
        Timestamp timestamp = new Timestamp(0);
        timestamp.setTime(milliSeconds);
        return DateUtil.format(timestamp, timeFormat);
    }

}
