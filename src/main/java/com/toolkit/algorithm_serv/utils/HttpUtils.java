package com.toolkit.algorithm_serv.utils;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.file.PathUtil;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;

public class HttpUtils {
    public static String uploadFile(MultipartFile multipartFile, boolean uuidName) throws IOException {
        if (multipartFile.isEmpty()) {
            throw new IllegalArgumentException("没有在请求中找到上传文件");
        }

        String fileName = multipartFile.getOriginalFilename();
        if (uuidName) {
            String extName = FileUtil.extName(fileName);
            fileName = StrAuxUtils.generateUuid() + "." + extName;
        }
        String filePath = FileUtils.joinPath(FileUtils.getWorkingPath(), "files", "upload", fileName);
        File dest = new File(filePath);
        multipartFile.transferTo(dest);

        return filePath;
    }

    public static ResponseEntity<byte[]> downloadFile(String filePath, boolean inline, String newFileName) throws IOException {
        byte[] data = FileUtil.readBytes(filePath);
        // 构建响应
        ResponseEntity.BodyBuilder bodyBuilder = ResponseEntity.ok();
        bodyBuilder.contentLength(data.length);
        // 二进制数据流
        bodyBuilder.contentType(MediaType.APPLICATION_OCTET_STREAM);
        // String filename = FileUtil.getName(filePath);
        if (!StrAuxUtils.isValid(newFileName)) {
            newFileName = FileUtil.getName(filePath);
        }

        String encodeFileName = URLEncoder.encode(newFileName, "UTF-8");
        // 其他浏览器
        if (inline) {
            // 在浏览器中打开
            File file = new File(filePath);
            URL url = new URL("file:///" + file);
            bodyBuilder.header("Content-Type", url.openConnection().getContentType());
            bodyBuilder.header("Content-Disposition", "inline;filename*=UTF-8''" + encodeFileName);
        } else {
            // 直接下载
            bodyBuilder.header("Content-Disposition", "attachment;filename*=UTF-8''" + encodeFileName);
        }

        // 下载成功返回二进制流
        return bodyBuilder.body(data);
    }

    public static ResponseEntity<byte[]> downloadFile(String filePath) throws IOException {
        return HttpUtils.downloadFile(filePath, false, "");
    }

    // public static ResponseEntity<byte[]> saveAs(String filePath, String newName) throws IOException {
    //     if (StrAuxUtils.isValid(newName)) {
    //         String dir = FileUtil.getParent(filePath, 1);
    //         filePath = FileUtils.joinPath(dir, newName);
    //     }
    //     return downloadFile(filePath, false, newName);
    // }
}
