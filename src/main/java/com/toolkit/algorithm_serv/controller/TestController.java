package com.toolkit.algorithm_serv.controller;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.utils.SystemUtils;
//import com.toolkit.algorithm_serv.global.cache.HostConfigs;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "*",maxAge = 3600)
@RequestMapping(value = "/test")
public class TestController {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    ResponseHelper responseHelper;

    /**
     * A.1 获取操作系统信息
     * @return
     */
    @RequestMapping(value = "/os", method = RequestMethod.GET)
    @ResponseBody
    public Object getOsInfo() {
        JSONObject jsonOS = new JSONObject();
        jsonOS.put("OS Name", SystemUtils.getOsName());
        jsonOS.put("OS Arch", SystemUtils.getOsArch());
        jsonOS.put("OS Version", SystemUtils.getOsVersion());
        return responseHelper.success(jsonOS);
    }

    /**
     * A.2 获取所有系统环境参数
     * @return
     */
    @RequestMapping(value = "/all-sys-props", method = RequestMethod.GET)
    @ResponseBody
    public Object getAllSystemProps() {
        return responseHelper.success(SystemUtils.sysProps);
    }

//    /**
//     * A.3 读取全局变量
//     * @param varType 全局变量类型
//     * @return
//     */
//    @RequestMapping(value = "/global-vars", method = RequestMethod.GET)
//    @ResponseBody
//    public Object getGlobalVars(@RequestParam("var_type") String varType) {
//        if (varType.equalsIgnoreCase("host")) {
//            JSONObject jsonResp = new JSONObject();
//            jsonResp.put("host_ip", HostConfigs.ip);
//            jsonResp.put("host_port", HostConfigs.port);
//            jsonResp.put("host_url_alive", HostConfigs.urlTestAlive);
//            return responseHelper.success(jsonResp);
//        }
//
//        return responseHelper.error(ErrorCodeEnum.ERROR_PARAMETER);
//    }

}
