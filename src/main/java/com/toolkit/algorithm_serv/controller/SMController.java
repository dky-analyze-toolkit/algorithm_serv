package com.toolkit.algorithm_serv.controller;

import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.global.utils.SecurityTestAll;
import com.toolkit.algorithm_serv.global.utils.Util;
import com.toolkit.algorithm_serv.global.utils.sm2.*;
import com.toolkit.algorithm_serv.global.utils.sm4.SM4Utils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.Random;

//import com.toolkit.algorithm_serv.global.cache.HostConfigs;

@RestController
@CrossOrigin(origins = "*",maxAge = 3600)
@RequestMapping(value = "/alg")
public class SMController {
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    ResponseHelper responseHelper;


    /**
     * 1.0 SM2
     * @return
     */
    @RequestMapping(value = "/generateKeyPair", method = RequestMethod.GET)
    @ResponseBody
    public Object generateKeyPair() throws Exception {

        SM2 sm2 = SM2.Instance();
        AsymmetricCipherKeyPair key = null;
        while (true){
            key=sm2.ecc_key_pair_generator.generateKeyPair();
            if(((ECPrivateKeyParameters) key.getPrivate()).getD().toByteArray().length==32){
                break;
            }
        }
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        BigInteger privateKey = ecpriv.getD();
        ECPoint publicKey = ecpub.getQ();
        SM2KeyVO sm2KeyVO = new SM2KeyVO();
        sm2KeyVO.setPublicKey(publicKey);
        sm2KeyVO.setPrivateKey(privateKey);
        //System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded()));
        //System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
//        return sm2KeyVO;

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("publickey", Util.byteToHex(publicKey.getEncoded()));
        jsonOS.put("privatekey", Util.byteToHex(privateKey.toByteArray()));
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.1 SM2签名
     * privatekey = "73e83d33d95274eeeb23f01834d02fe920b4afece377410435698dfdf1d84203";
     * srchex = "0653F3748DFD938FE83935800FF3F526B85C30C2331DD56FCB1794AA99F2A416";
     * @return
     */
    @RequestMapping(value = "/sm2sign", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2sign(@RequestParam("privatekey") String privatekey,
                          @RequestParam("srchex") String srchex) throws Exception {

        SM2SignVO sign = SM2SignVerUtils.Sign2SM2(Util.hexStringToBytes(privatekey), Util.hexToByte(srchex));
        System.out.println("R:"+sign.sign_r);
        System.out.println("S:"+sign.sign_s);
//        System.out.println("sign_express:"+sign.sign_express);
//        System.out.println("sm2_sign:"+sign.sm2_sign);
//        System.out.println("sm2_type:"+sign.sm2_type);
//        System.out.println("sm2_userd:"+sign.sm2_userd);
        System.out.println("getSm2_signForHard():"+sign.getSm2_signForHard());
        System.out.println("getSm2_signForSoft():"+sign.getSm2_signForSoft());

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("sign_r", sign.sign_r);
        jsonOS.put("sign_s", sign.sign_s);
        jsonOS.put("asn1", sign.getSm2_signForSoft());
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.2 SM2验签
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
        jsonOS.put("result", verify.isVerify());
        return responseHelper.success(jsonOS);
    }
    /**
     * 1.3 SM2加密
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
     * @return
     */
    @RequestMapping(value = "/sm2dec", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2dec(@RequestParam("privatekey") String privatekey,
                       @RequestParam("cipherhex") String cipherhex) throws Exception {

        System.out.println("解密: ");
        String plainText = new String(SM2EncDecUtils.decrypt(Util.hexToByte(privatekey), Util.hexToByte(cipherhex)));
        System.out.println(plainText);

        String hex = Util.byteToHex(plainText.getBytes());

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("plainText", plainText);
        jsonOS.put("plainHex", hex);
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.5 SM3Digest
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

        String hex = Util.byteToHex(plainText.getBytes());

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("plainText", plainText);
        jsonOS.put("plainHex", hex);
        return responseHelper.success(jsonOS);
    }

    /**
     * 1.8 SM4sm4generatekey
     * @return
     */
    @RequestMapping(value = "/sm4generatekey", method = RequestMethod.GET)
    @ResponseBody
    public Object sm4generatekey() throws Exception {
        int len = 32;
        String str = "";
        for (int i = 0; i < len; i++) {
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
            str = str + temp;
        }
        JSONObject jsonOS = new JSONObject();
        jsonOS.put("key", str.toUpperCase());
        return responseHelper.success(jsonOS);
    }
    /**
     * 1.9 string2hex
     * @return
     */
    @RequestMapping(value = "/string2hex", method = RequestMethod.GET)
    @ResponseBody
    public Object string2hex(@RequestParam("string") String str) throws Exception {

        String hex = Util.byteToHex(str.getBytes());

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("hexstring", hex);
        return responseHelper.success(jsonOS);
    }
    /**
     * 1.10 hex2string
     * @return
     */
    @RequestMapping(value = "/hex2string", method = RequestMethod.GET)
    @ResponseBody
    public Object hex2string(@RequestParam("hex") String hex) throws Exception {

        String str = Util.hexStringToString(hex,2);

        JSONObject jsonOS = new JSONObject();
        jsonOS.put("string", str.toUpperCase());
        return responseHelper.success(jsonOS);
    }

}