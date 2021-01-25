package com.toolkit.algorithm_serv.controller;

import cn.hutool.core.convert.Convert;
import cn.hutool.core.util.CharsetUtil;
import com.alibaba.fastjson.JSONObject;
import com.toolkit.algorithm_serv.algorithm.hash.HashHelper;
import com.toolkit.algorithm_serv.global.enumeration.ErrorCodeEnum;
import com.toolkit.algorithm_serv.global.response.ResponseHelper;
import com.toolkit.algorithm_serv.utils_ex.Util;
import com.toolkit.algorithm_serv.algorithm.sm2.*;
import com.toolkit.algorithm_serv.algorithm.sm4.SM4Utils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;

//import com.toolkit.algorithm_serv.global.cache.HostConfigs;

@RestController
@CrossOrigin(origins = "*",maxAge = 3600)
@RequestMapping(value = "/alg")
public class SMApi {
    private String defaultIV = "30303030303030303030303030303030";
    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ResponseHelper responseHelper;

    @Autowired
    public SMApi(ResponseHelper responseHelper) {
        this.responseHelper = responseHelper;
    }


    /**
     * 1.0 SM2
     * @return
     */
    @RequestMapping(value = "/generateKeyPair", method = RequestMethod.GET)
    @ResponseBody
    public Object generateKeyPair() {
        try{
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
        catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }

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
                          @RequestParam(value = "user_id", required = false) String userID,
                          @RequestParam("srchex") String srchex) {

        try {
            SM2SignVO sign = SM2SignVerUtils.Sign2SM2(Util.hexStringToBytes(privatekey), Util.hexToByte(srchex), userID);
            System.out.println("R:" + sign.sign_r);
            System.out.println("S:" + sign.sign_s);
            System.out.println("getSm2_signForHard():" + sign.getSm2_signForHard());
            System.out.println("getSm2_signForSoft():" + sign.getSm2_signForSoft());

            JSONObject jsonOS = new JSONObject();
            jsonOS.put("sign_r", sign.sign_r);
            jsonOS.put("sign_s", sign.sign_s);
            jsonOS.put("asn1", sign.getSm2_signForSoft());
            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException argEx) {
            return responseHelper.error(ErrorCodeEnum.ERROR_PARAM_LENGTH);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_SIGN);
        }
    }

    /**
     * 1.2 SM2验签
     * @return
     */
    @RequestMapping(value = "/sm2verify", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2verify(@RequestParam("publickey") String publickey,
                            @RequestParam(value = "user_id", required = false) String userID,
                            @RequestParam("srchex") String srchex,
                            @RequestParam("signhex") String signhex  ) {

        try {
            SM2SignVO verify = SM2SignVerUtils.VerifySignSM2(Util.hexStringToBytes(publickey), Util.hexToByte(srchex),
                    Util.hexToByte(SM2SignVerUtils.SM2SignHardToSoft(signhex)), userID);
            System.err.println("验签结果" + verify.isVerify());

            JSONObject jsonOS = new JSONObject();
            jsonOS.put("result", verify.isVerify());
            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException argEx) {
            return responseHelper.error(ErrorCodeEnum.ERROR_PARAM_LENGTH);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_VERIFY_SIGN);
        }
    }
    /**
     * 1.3 SM2加密
     * @return
     */
    @RequestMapping(value = "/sm2enc", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2enc(@RequestParam("publickey") String publicKey,
                         @RequestParam("plainhex") String src,
                         @RequestParam(value = "cipher_format", required = false) String cipherFormat) {
        try {
            byte[] sourceData = Util.hexToByte(src);

            boolean oldVer = false;
            if (cipherFormat != null) {
                oldVer = cipherFormat.equalsIgnoreCase("c1c2c3");
            }
            String cipherText = SM2EncDecUtils.encrypt(Util.hexToByte(publicKey), sourceData, oldVer);
            System.out.println(cipherText);
            JSONObject jsonOS = new JSONObject();
            jsonOS.put("cipherText", cipherText);
            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException argEx) {
            return responseHelper.error(ErrorCodeEnum.ERROR_PARAM_LENGTH);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
        }
    }

    /**
     * 1.4 SM2解密
     * @return
     */
    @RequestMapping(value = "/sm2dec", method = RequestMethod.GET)
    @ResponseBody
    public Object sm2dec(@RequestParam("privatekey") String privatekey,
                         @RequestParam("cipherhex") String cipherhex,
                         @RequestParam(value = "cipher_format", required = false) String cipherFormat) {

        try {
            boolean oldVer = false;
            if (cipherFormat != null) {
                oldVer = cipherFormat.equalsIgnoreCase("c1c2c3");
            }

            byte[] plainBytes = SM2EncDecUtils.decrypt(Util.hexToByte(privatekey), Util.hexToByte(cipherhex), oldVer);
            if (plainBytes.length > 0) {
                JSONObject jsonOS = new JSONObject();
                jsonOS.put("plainText", new String(plainBytes, "UTF-8"));
                jsonOS.put("plainHex", Util.byteToHex(plainBytes));

                return responseHelper.success(jsonOS);
            } else {
                return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_DECRYPT);
            }
        } catch (IllegalArgumentException argEx) {
            return responseHelper.error(ErrorCodeEnum.ERROR_PARAM_LENGTH);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
        }
    }

    /**
     * 1.5 SM3Digest
     * @return
     */
    @RequestMapping(value = "/sm3digest", method = RequestMethod.GET)
    @ResponseBody
    public Object sm3(@RequestParam("srchex") String srchex) {
        try{
            JSONObject jsonOS = new JSONObject();
            jsonOS.put("SM3Digest", HashHelper.sm3(srchex).toUpperCase());
            return responseHelper.success(jsonOS);
        }
        catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

    /**
     * 1.6 SM4加密
     * @return
     */
    @RequestMapping(value = "/sm4enc", method = RequestMethod.GET)
    @ResponseBody
    public Object sm4enc(@RequestParam("key") String key,
                         @RequestParam("plainhex") String plainhex,
                         @RequestParam("mode") String mode,
                         @RequestParam(value = "iv", required = false) String iv) {
        try {
            byte[] sourceData = Util.hexToByte(plainhex);

            SM4Utils sm4 = new SM4Utils();
            sm4.secretKey = key;
            sm4.hexString = true;
            String cipherText = "";
            if (iv == null || iv.isEmpty()) {
                sm4.iv = defaultIV;
            } else {
                sm4.iv = iv;
            }
            if (mode.equals("ECB")) {
                cipherText = sm4.encryptData_ECB_hex(sourceData);
            } else if (mode.equals("CBC")) {
                cipherText = sm4.encryptData_CBC_hex(sourceData);
            }
            if (cipherText == null) {
                return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_ENCRYPT);
            }

            JSONObject jsonOS = new JSONObject();
            jsonOS.put("cipherText", cipherText);
            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException argEx) {
            return responseHelper.error(ErrorCodeEnum.ERROR_PARAM_LENGTH);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
        }
    }

    /**
     * 1.7 SM4解密
     * @return
     */
    @RequestMapping(value = "/sm4dec", method = RequestMethod.GET)
    @ResponseBody
    public Object sm4dec(@RequestParam("key") String key,
                         @RequestParam("cipherhex") String cipherhex,
                         @RequestParam("mode") String mode,
                         @RequestParam(value = "iv", required = false) String iv) {

        try {
            SM4Utils sm4 = new SM4Utils();
            sm4.secretKey = key;
            sm4.hexString = true;
            if (iv == null || iv.isEmpty()) {
                sm4.iv = defaultIV;
            } else {
                sm4.iv = iv;
            }
            String plainHex = "";
            byte[] encData = Util.hexToByte(cipherhex);
            if (mode.equals("ECB")) {
                plainHex = sm4.decryptData_ECB_hex(encData);
            } else if (mode.equals("CBC")) {
                plainHex = sm4.decryptData_CBC_hex(encData);
            }

            if (plainHex == null || plainHex.isEmpty()) {
                return responseHelper.error(ErrorCodeEnum.ERROR_FAIL_DECRYPT);
            }
            JSONObject jsonOS = new JSONObject();
            jsonOS.put("plainText", new String(Util.hexToByte(plainHex), "UTF-8"));
            jsonOS.put("plainHex", plainHex);
            return responseHelper.success(jsonOS);
        } catch (IllegalArgumentException argEx) {
            return responseHelper.error(ErrorCodeEnum.ERROR_PARAM_LENGTH);
        } catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR);
        }
    }

    /**
     * 1.8 SM4sm4generatekey
     * @return
     */
    @RequestMapping(value = "/sm4generatekey", method = RequestMethod.GET)
    @ResponseBody
    public Object sm4generatekey() {
        try{
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
        }        catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }
    /**
     * 1.9 string2hex
     * @return
     */
    @RequestMapping(value = "/string2hex", method = RequestMethod.GET)
    @ResponseBody
    public Object string2hex(@RequestParam("string") String str) throws Exception {

        try{
            JSONObject jsonOS = new JSONObject();
            jsonOS.put("hexstring", Convert.toHex(str, CharsetUtil.CHARSET_UTF_8));
            return responseHelper.success(jsonOS);
        }
        catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }
    /**
     * 1.10 hex2string
     * @return
     */
    @RequestMapping(value = "/hex2string", method = RequestMethod.GET)
    @ResponseBody
    public Object hex2string(@RequestParam("hex") String hex) throws Exception {

        try{
            JSONObject jsonOS = new JSONObject();
            jsonOS.put("string", Convert.hexToStr(hex, CharsetUtil.CHARSET_UTF_8));
            return responseHelper.success(jsonOS);
        }
        catch (Exception e) {
            return responseHelper.error(ErrorCodeEnum.ERROR_GENERAL_ERROR, e.getMessage());
        }
    }

}
