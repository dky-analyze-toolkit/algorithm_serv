package com.toolkit.algorithm_serv.services.system;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.io.IORuntimeException;
import cn.hutool.core.io.file.FileReader;
import cn.hutool.core.io.file.FileWriter;
import cn.hutool.system.oshi.OshiUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.hmac.HMacHelper;
import com.toolkit.algorithm_serv.services.sys_auth.SystemAuthHelper;
import com.toolkit.algorithm_serv.utils.TimeUtils;
import oshi.hardware.*;

import javax.swing.filechooser.FileSystemView;

public class SystemManageHelper {

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

}
