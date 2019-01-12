package com.duangframework.encrypt.core;

import com.duangframework.encrypt.algorithm.PKCS7Algorithm;
import com.duangframework.encrypt.algorithm.Pbkdf2Sha256Algorithm;
import com.duangframework.encrypt.algorithm.Sha256Algorithm;

import java.util.Map;

/**
 * Created by laotang on 2019/1/1.
 */
public class EncryptFactory {

    // 签名算法
    private static final Sha256Algorithm sha256Algorithm = new Sha256Algorithm();
    // 密码算法
    private static final Pbkdf2Sha256Algorithm pbkdf2Sha256Algorithm = new Pbkdf2Sha256Algorithm();
    // 参数加密算法
    private static final PKCS7Algorithm pkcs7Algorithm = new PKCS7Algorithm();

    // 签名
    public static String signSha256(EncryptDto encryptDto, String secret) {
        return sha256Algorithm.encrypt(secret, encryptDto);
    }


    /**
     * 密码加密
     * @param password  明文密码
     * @param salt  盐值
     * @return
     */
    public static String encrypt4Pwd(String password, String salt) {
        return pbkdf2Sha256Algorithm.encode(password, salt);
    }

    /**
     * 参数加密
     * @param replyMsg
     * @param secret
     * @return
     */
    public static String encrypt(String replyMsg, String secret) {
        pkcs7Algorithm.setSymmetricKey(secret);
        return pkcs7Algorithm.encrypt(replyMsg);
    }

    /**
     *
     * @param target
     * @param headerMap
     * @param paramMap
     * @param secret
     * @return
     * @throws Exception
     */
    public static String valid(String target, Map<String,String> headerMap, Map<String,Object> paramMap, String secret) throws Exception {
        return EncryptUtils.valid(target, headerMap, paramMap, secret);
    }

}
