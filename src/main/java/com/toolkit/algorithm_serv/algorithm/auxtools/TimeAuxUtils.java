package com.toolkit.algorithm_serv.algorithm.auxtools;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;

import java.sql.Timestamp;

public class TimeAuxUtils {

    public static String time2stamp(String timeStr) throws IllegalArgumentException {
        try {

            DateTime datetime = DateUtil.parse(timeStr);
            Long milliSeconds = Timestamp.valueOf(datetime.toString()).getTime();
            return milliSeconds.toString();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String stamp2time(String stampStr,String timeFormat) throws IllegalArgumentException {
        try {
            Timestamp timestamp = new Timestamp(0);
            timestamp.setTime(Long.valueOf(stampStr));
//TODO
//            DateTime datetime = DateUtil.parse(timeStr);
//            datetime.
//            DateUtil.format()
//            timestamp.
            return timestamp.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
