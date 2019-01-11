package com.duangframework.encrypt.algorithm;

import com.duangframework.encrypt.core.Base64;
import com.duangframework.encrypt.core.EncryptDto;
import com.duangframework.encrypt.core.EncryptFactory;
import com.duangframework.encrypt.core.EncryptUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HmacSHA256 算法
 *
 *  一般用于提交的参数进行签名
 *
 */
public class Sha256Algorithm {

    private static final String SHA256_ALG         = "HmacSHA256";
    private static final String DEFAULT_CHAR_ENCODE = "UTF-8";


    /**
     * SHA256对称加密
     * @param appSecret 安全码作为密钥
     * @param dto   加密内容对象
     * @return
     * @throws SecurityException
     */
    public String encrypt(String appSecret, EncryptDto dto) throws SecurityException {
        try {
            byte[] signResult = encryptByte(appSecret, dto);
            //对字符串进行hmacSha256加密，然后再进行BASE64编码
            return Base64.encode(signResult);
        } catch (Exception e) {
            throw new IllegalArgumentException("create signature failed.", e);
        }
    }


    private byte[] encryptByte(String appSecret, EncryptDto dto) throws SecurityException {
        try {
            Mac hmacSha256 = Mac.getInstance(SHA256_ALG);
            byte[] keyBytes = appSecret.getBytes(DEFAULT_CHAR_ENCODE);
            hmacSha256.init(new SecretKeySpec(keyBytes, 0, keyBytes.length, SHA256_ALG));
            String encryptContent = EncryptUtils.buildEncryptString(dto);
            return hmacSha256.doFinal(encryptContent.getBytes(DEFAULT_CHAR_ENCODE));
        } catch (Exception e) {
            throw new IllegalArgumentException("create signature failed.", e);
        }
    }
}
