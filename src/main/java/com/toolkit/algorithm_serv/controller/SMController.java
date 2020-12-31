package com.toolkit.algorithm_serv.controller;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.global.utils.SecurityTestAll;
import com.toolkit.algorithm_serv.global.utils.Util;
import com.toolkit.algorithm_serv.global.utils.sm2.SM2EncDecUtils;
import com.toolkit.algorithm_serv.global.utils.sm2.SM2SignVO;
import com.toolkit.algorithm_serv.global.utils.sm2.SM2SignVerUtils;
import com.toolkit.algorithm_serv.global.utils.sm4.SM4Utils;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

//import com.toolkit.algorithm_serv.global.cache.HostConfigs;

@RestController
@CrossOrigin(origins = "*",maxAge = 3600)
@RequestMapping(value = "/alg")
public class SMController {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    ResponseHelper responseHelper;

    /**
     * 1.1 SM2签名
     * publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm2sign", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2sign(@RequestParam("privatekey") String privatekey,
                          @RequestParam("srchex") String srchex) throws Exception {

        SM2SignVO sign = SM2SignVerUtils.Sign2SM2(Util.hexStringToBytes(privatekey), Util.hexToByte(srchex));
        System.out.println("R:"+sign.sign_r);
        System.out.println("S:"+sign.sign_s);

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("sign_r", sign.sign_r);
        jsonOS.put("sign_s", sign.sign_s);
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.2 SM2验签
     * publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm2verify", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2verify(@RequestParam("publickey") String publickey,
                            @RequestParam("srchex") String srchex,
                            @RequestParam("signhex") String signhex  ) throws Exception {

        SM2SignVO verify = SM2SignVerUtils.VerifySignSM2(Util.hexStringToBytes(publickey), Util.hexToByte(srchex), Util.hexToByte(SecurityTestAll.SM2SignHardToSoft(signhex)));
        System.err.println("验签结果" + verify.isVerify());

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("验签结果", verify.isVerify());
        return responseHelper.success(jsonOS);
    }
    /**
     * 1.3 SM2加密
     * publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm2enc", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2enc(@RequestParam("publickey") String publicKey,
                        @RequestParam("plainhex") String src) throws Exception {

//        String plainText = "ILoveYou11";
//        byte[] sourceData1 = plainText.getBytes();
        byte[] sourceData = Util.hexToByte(src);

        System.out.println("加密: ");
        String cipherText = SM2EncDecUtils.encrypt(Util.hexToByte(publicKey), sourceData);
        System.out.println(cipherText);
        JSONObject jsonOS = new JSONObject();
        jsonOS.put("cipherText", cipherText);
        return responseHelper.success(jsonOS);

    }

    /**
     * 1.4 SM2解密
     * publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm2dec", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2dec(@RequestParam("privatekey") String privatekey,
                       @RequestParam("cipherhex") String cipherhex) throws Exception {

        System.out.println("解密: ");
        String plainText = new String(SM2EncDecUtils.decrypt(Util.hexToByte(privatekey), Util.hexToByte(cipherhex)));
        System.out.println(plainText);

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("plainText", plainText);
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.5 SM3Digest
     * publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm3digest", method = RequestMethod.GET)
    @ResponseBody
    public Object sm3(@RequestParam("srchex") String srchex) throws Exception {
        byte[] md = new byte[32];
        byte[] msg1 = Util.hexToByte(srchex);
//        byte[] msg1 = "ererfeiisgod".getBytes();
        System.out.println(Util.byteToHex(msg1));
        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg1, 0, msg1.length);
        sm3.doFinal(md, 0);
        String s = new String(Hex.encode(md));
        System.out.println(s.toUpperCase());

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("SM3Digest", s.toUpperCase());
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.6 SM4加密
     * publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm4enc", method = RequestMethod.GET)
    @ResponseBody
    public Object sm4enc(@RequestParam("key") String key,
                         @RequestParam("plainhex") String plainhex,
                         @RequestParam("mode") String mode) throws Exception {
        byte[] sourceData = Util.hexToByte(plainhex);

        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = key;
        sm4.hexString = true;
        String cipherText="";
        if(mode.equals("ECB"))
        {
            System.out.println("ECB模式加密");
            cipherText = sm4.encryptData_ECB_hex(sourceData);
            System.out.println("密文: " + cipherText);
            System.out.println("");

        }
        else if(mode.equals("CBC"))
        {
            System.out.println("CBC模式加密");
            sm4.iv = "30303030303030303030303030303030";
            cipherText = sm4.encryptData_CBC_hex(sourceData);
            System.out.println("加密密文: " + cipherText);
            System.out.println("");

        }

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("cipherText", cipherText);
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.4 SM4解密
     * publicKey = "042780f0963a428a7b030ac1c14a90b967bf365f5394ebf1f0ca1598d4d9bece4fdfa05ba043817fef68bef497088e3992362ce55b1858444fa5a3e00c5042b207";
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * src = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm4dec", method = RequestMethod.GET)
    @ResponseBody
    public Object sm4dec(@RequestParam("key") String key,
                         @RequestParam("cipherhex") String cipherhex,
                         @RequestParam("mode") String mode) throws Exception {

        byte[] sourceData = Util.hexToByte(cipherhex);

        SM4Utils sm4 = new SM4Utils();
        sm4.secretKey = key;
        sm4.hexString = true;
        sm4.iv = "30303030303030303030303030303030";
        String plainText="";
        if(mode.equals("ECB"))
        {
            System.out.println("ECB模式解密");
            byte[] encData = Util.hexToByte(cipherhex);
            plainText = sm4.decryptData_ECB_hex(encData);
            System.out.println("明文: " + plainText);
            System.out.println("");
        }
        else if(mode.equals("CBC"))
        {
            System.out.println("CBC模式解密");
            byte[] encData = Util.hexToByte(cipherhex);
            plainText = sm4.decryptData_CBC_hex(encData);
            System.out.println("明文: " + plainText);
            System.out.println("");

        }

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("plainText", plainText);
        return responseHelper.success(jsonOS);
    }


}
