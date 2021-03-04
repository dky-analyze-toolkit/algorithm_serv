package com.toolkit.algorithm_serv.services.pwd_crack;

import cn.hutool.core.io.FileUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.global.enumeration.TaskRunStatusEnum;
import com.toolkit.algorithm_serv.global.notify.NotifyHandler;
import com.toolkit.algorithm_serv.utils.FixedTaskPool;
import com.toolkit.algorithm_serv.utils.StrAuxUtils;
import com.toolkit.algorithm_serv.utils.SysAuxUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

@Component
public class CrackPwdTask extends FixedTaskPool {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());
    private static ArrayList<WorkThread> tasks = new ArrayList<WorkThread>();
    private final NotifyHandler notifyHandler;
    // private static WorkThread[] tasks = ArrayUtil.newArray(WorkThread.class, 10);

    @Autowired
    public CrackPwdTask(NotifyHandler notifyHandler) {
        super();
        this.notifyHandler = notifyHandler;
    }

    public class WorkThread implements Runnable {
        protected Logger inLogger = LoggerFactory.getLogger(this.getClass());
        private String crackFileName;
        private String taskUuid;
        private JSONObject taskInfo;
        // private NotifyHandler notifyHandler;
        private String clientID;
        private Process crackProc;

        public WorkThread(String crackFileName, String taskUuid, String clientID) {
            this.crackFileName = crackFileName;
            this.taskUuid = taskUuid;
            this.clientID = clientID;

            this.taskInfo = new JSONObject();
            taskInfo.put("uuid", taskUuid);
            setTaskStatus(TaskRunStatusEnum.IDLE);

            crackProc = null;
            // notifyHandler = new NotifyHandler();

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

        public void setTaskStart() {
            inLogger.info("Thread-" + Thread.currentThread().getId() + " start.");
            inLogger.info("CrackFile=" + crackFileName);
            inLogger.info("TaskUuid=" + taskUuid);
            setTaskStatus(TaskRunStatusEnum.RUNNING);
            setPercent(0.0);

            notifyHandler.sendToClient(clientID, taskInfo);
        }

        public void setTaskComplete() {
            setTaskStatus(TaskRunStatusEnum.FINISHED);
            setPercent(100.0);

            notifyHandler.sendToClient(clientID, taskInfo);
            inLogger.info("Thread-" + Thread.currentThread().getId() + " end.");
        }

        public boolean isRunning() {
            return getTaskStatus().equals( TaskRunStatusEnum.RUNNING.toString() );
        }

        public void cancel() {
            if (isRunning()) {
                setTaskStatus(TaskRunStatusEnum.INTERRUPTED);
                JtrHelper.stopCrack(crackProc);
            }
        }

        @Override
        public void run() {
            setTaskStart();

            crackFilePassword();

            if (isRunning()) {
                setTaskComplete();
            } else {
                notifyHandler.sendToClient(clientID, taskInfo);
            }
        }

        private void crackFilePassword() {
            try {
                Thread.sleep(10);

                if (isRunning()) {
                    String hashFilePath = JtrHelper.extractHash(crackFileName);

                    if (isRunning()) {
                        crackProc = JtrHelper.crackHash(hashFilePath);
                        BufferedReader reader = SysAuxUtils.getProcReader(crackProc);
                        String line;
                        while ((line = reader.readLine()) != null) {
                            logger.info(line);
                        }
                        reader.close();
                    }

                    if (isRunning()) {
                        String password = JtrHelper.getCrackedPwd(hashFilePath);
                        taskInfo.put("result", password);
                    }
                }

                // Thread.sleep(3000);
                // taskInfo.put("result", "Complete");
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }
        }

    }

    public String addTask(String filePath, String clientID) {
        String taskUuid = StrAuxUtils.generateUuid();
        WorkThread work = new WorkThread(filePath, taskUuid, clientID);
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

    public void stopTask(String taskUuid) {
        WorkThread task = getTask(taskUuid);
        task.cancel();
    }

}
