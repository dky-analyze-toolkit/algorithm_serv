package com.toolkit.algorithm_serv.algorithm.auxtools;

import cn.hutool.core.codec.Base64;
import com.alibaba.fastjson.JSONObject;

public class JsonResultHelper {
    public static void putHexSize(JSONObject jsonResult, String hex) {
        jsonResult.put("size", hex.length() / 2);
        jsonResult.put("bits", hex.length() / 2 * 8);
    }

    public static void jsonPutHex(JSONObject jsonResult, String key, String value) {
        jsonResult.put(key + "_hex", value);
        jsonResult.put(key + "_b64", Base64.encode(value));
        putHexSize(jsonResult, value);
    }

}
