package com.toolkit.algorithm_serv.utils;

import org.springframework.stereotype.Component;

import java.util.concurrent.*;

@Component
public class FixedTaskPool {
    private static ExecutorService fixedPool = null;

    public FixedTaskPool(int poolSize) {
        initPool(poolSize);
    }

    public FixedTaskPool() {
        initPool(0);
    }

    private void initPool(int poolSize) {
        if (fixedPool == null) {
            if (poolSize <= 0) {
                poolSize = 4;
            }
            fixedPool = Executors.newFixedThreadPool(poolSize);
        }
    }

    public void execute(Runnable work) {
        fixedPool.execute(work);
    }

    public void shutdown() {
        fixedPool.shutdown();
    }

    public void shutdownNow() {
        fixedPool.shutdownNow();
    }
}
