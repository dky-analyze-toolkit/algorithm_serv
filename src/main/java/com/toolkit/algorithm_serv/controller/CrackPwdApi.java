package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.io.FileUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.global.annotation.*;
import com.toolkit.algorithm_serv.global.notify.NotifyHandler;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.services.pwd_crack.CrackPwdTask;
import com.toolkit.algorithm_serv.services.pwd_crack.CrackUploadFile;
import com.toolkit.algorithm_serv.services.pwd_crack.WordPwdCrack;
import com.toolkit.algorithm_serv.utils.FileUtils;
import com.toolkit.algorithm_serv.utils.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@SysAuth
@RequestMapping(value = "/crack-pwd")
public class CrackPwdApi {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;
    private final CrackUploadFile crackUploadFile;
    private final CrackPwdTask crackPwdTask;
    private final NotifyHandler notifyHandler;

    @Autowired
    public CrackPwdApi(ResponseHelper responseHelper, CrackUploadFile crackUploadFile, CrackPwdTask crackPwdTask, NotifyHandler notifyHandler) {
        this.responseHelper = responseHelper;
        this.crackUploadFile = crackUploadFile;
        this.crackPwdTask = crackPwdTask;
        this.notifyHandler = notifyHandler;
    }

    @PostMapping("upload")
    @ResponseBody
    public Object uploadDestFile(@RequestParam("file_item") MultipartFile file_item) throws IOException {
        String fileName = crackUploadFile.saveUploadFile(file_item);
        return responseHelper.success(fileName);
    }

    @PostMapping("/word/remove-pwd")
    @ResponseBody
    public Object removeWordPwd(
            @RequestParam("file_item") MultipartFile wordFile,
            @RequestParam(value = "download", required = false, defaultValue = "0") boolean download
    ) throws IOException {
        String filePath = HttpUtils.uploadFile(wordFile, false);

        String unlockedFile = WordPwdCrack.crackFile(filePath);
        if (download) {
            return HttpUtils.downloadFile(unlockedFile);
        } else {
            return responseHelper.success(unlockedFile);
        }
    }

    @PostMapping("/office/remove-pwd")
    @ResponseBody
    public Object removeOfficePwd(
            @RequestParam("file_name") String fileName,
            @RequestParam(value = "download", required = false, defaultValue = "0") boolean download,
            @RequestParam(value = "new_name", required = false, defaultValue = "") String newFileName
    ) throws IOException {
        String filePath = FileUtils.joinPath(FileUtils.getWorkingPath(), "files", "upload", fileName);

        String unlockedFile = WordPwdCrack.crackFile(filePath);
        if (download) {
            return HttpUtils.downloadFile(unlockedFile, false, newFileName);
        } else {
            return responseHelper.success(FileUtil.getName(unlockedFile));
        }
    }

    @GetMapping("download")
    @ResponseBody
    public Object download(
            @RequestParam("file_name") String fileName,
            @RequestParam(value = "new_name", required = false, defaultValue = "") String newFileName
    ) throws IOException {
        String filePath = FileUtils.joinPath(FileUtils.getWorkingPath(), "modules", "craXcel-cli", "unlocked", fileName);
        return HttpUtils.downloadFile(filePath, false, newFileName);
    }

    @PostMapping("/run-task")
    @ResponseBody
    public Object runCrackTask(
            @RequestParam("file_name") String fileName,
            @RequestParam(value = "client_id", required = false, defaultValue = "0") String clientId
    ) {
        String filePath = FileUtils.joinPath(FileUtils.getWorkingPath(), "files", "upload", fileName);
        String taskUuid = crackPwdTask.addTask(filePath, clientId);
        JSONObject info = crackPwdTask.getTaskInfo(taskUuid);
        return responseHelper.success(info);
    }

    @GetMapping("task-info")
    @ResponseBody
    public Object getTaskInfo(@RequestParam("task_uuid") String taskUuid) {
        JSONObject info = crackPwdTask.getTaskInfo(taskUuid);
        return responseHelper.success(info);
    }

    @DeleteMapping("stop-task")
    @ResponseBody
    public Object stopCrackTask(@RequestParam("task_uuid") String taskUuid) {
        crackPwdTask.stopTask(taskUuid);
        return responseHelper.success();
    }

    @GetMapping("test-ws-client")
    @ResponseBody
    public Object test() {
        notifyHandler.sendToClient("123", "222");
        return responseHelper.success();
    }

}
