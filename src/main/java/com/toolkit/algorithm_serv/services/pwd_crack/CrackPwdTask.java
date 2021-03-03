package com.toolkit.algorithm_serv.services.pwd_crack;

import cn.hutool.core.io.FileUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.global.enumeration.TaskRunStatusEnum;
import com.toolkit.algorithm_serv.utils.FixedTaskPool;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import com.toolkit.algorithm_serv.utils.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

@Component
public class CrackPwdTask extends FixedTaskPool {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());
    private static ArrayList<WorkThread> tasks = new ArrayList<WorkThread>();
    // private static WorkThread[] tasks = ArrayUtil.newArray(WorkThread.class, 10);

    public CrackPwdTask() {
        super();
    }

    public class WorkThread implements Runnable {
        protected Logger inLogger = LoggerFactory.getLogger(this.getClass());
        private String crackFileName;
        private String taskUuid;
        private JSONObject taskInfo;

        public WorkThread(String crackFileName, String taskUuid) {
            this.crackFileName = crackFileName;
            this.taskUuid = taskUuid;

            this.taskInfo = new JSONObject();
            taskInfo.put("uuid", taskUuid);
            setTaskStatus(TaskRunStatusEnum.IDLE);
        }

        public void setTaskStatus(TaskRunStatusEnum status) {
            taskInfo.put("status", status.toString());
        }

        public String getTaskStatus() {
            return taskInfo.getString("status");
        }

        public void setPercent(double percent) {
            taskInfo.put("percent", percent);
        }

        public double getPercent() {
            return taskInfo.getDoubleValue("percent");
        }

        public JSONObject getTaskInfo() {
            return taskInfo;
        }

        public String getTaskUuid() {
            return taskUuid;
        }

        @Override
        public void run() {
            inLogger.info("Thread-" + Thread.currentThread().getId() + " start.");
            inLogger.info("CrackFile=" + crackFileName);
            inLogger.info("TaskUuid=" + taskUuid);
            setTaskStatus(TaskRunStatusEnum.RUNNING);
            setPercent(0.0);

            crackFilePassword();

            setTaskStatus(TaskRunStatusEnum.FINISHED);
            setPercent(100.0);
            inLogger.info("Thread-" + Thread.currentThread().getId() + " end.");
        }

        private void crackFilePassword() {
            try {
                Thread.sleep(10);

                String hashFilePath = JtrHelper.extractHash(crackFileName);

                ArrayList<String> results = JtrHelper.crackHash(hashFilePath);

                String password = JtrHelper.getCrackedPwd(hashFilePath);
                taskInfo.put("result", password);

                // Thread.sleep(3000);
                // taskInfo.put("result", "Complete");
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }
        }

    }

    public String addTask(String filePath) {
        String taskUuid = StrAuxUtils.generateUuid();
        WorkThread work = new WorkThread(filePath, taskUuid);
        tasks.add(work);

        this.execute(work);

        return taskUuid;
    }

    private WorkThread getTask(String uuid) {
        for (WorkThread work: tasks) {
            String taskUuid = work.getTaskUuid();
            if (taskUuid.equals(uuid))
                return work;
        }
        return null;
    }

    public String getTaskStatus(String taskUuid) {
        WorkThread task = getTask(taskUuid);
        return (task != null) ? task.getTaskStatus() : TaskRunStatusEnum.UNKNOWN.toString();
    }

    public JSONObject getTaskInfo(String taskUuid) {
        WorkThread task = getTask(taskUuid);
        return (task != null) ? task.getTaskInfo() : null;
    }

}
