package com.toolkit.algorithm_serv.algorithm.auxtools;
import com.google.common.base.Preconditions;

public class RandomHelper {
    public static String generateRandom(int randomLen) throws IllegalArgumentException {
        Preconditions.checkArgument(randomLen >= 1 && randomLen <= 256, "指定的长度: %s 无效，取值范围应为1-256字节", randomLen);
        try {
            String random = "";
            for (int i = 0; i < randomLen*2; i++) {
                char temp = 0;
                int key = (int) (Math.random() * 2);
                switch (key) {
                    case 0:
                        temp = (char) (Math.random() * 10 + 48);//产生随机数字
                        break;
                    case 1:
                        temp = (char) (Math.random() * 6 + 'a');//产生a-f
                        break;
                    default:
                        break;
                }
                random = random + temp;
            }

            return random.toUpperCase();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
