package com.toolkit.algorithm_serv.services.pwd_crack;

import cn.hutool.core.io.FileUtil;
import com.toolkit.algorithm_serv.utils.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Component
public class CrackUploadFile {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    public String saveUploadFile(MultipartFile fileItem) throws IOException {
        String filePath = HttpUtils.uploadFile(fileItem, true);

        return FileUtil.getName(filePath);
    }
}
