package com.duangframework.encrypt.core;

import com.duangframework.encrypt.algorithm.PKCS7Algorithm;
import com.duangframework.encrypt.algorithm.Pbkdf2Sha256Algorithm;
import com.duangframework.encrypt.algorithm.SHA1Algorithm;
import com.duangframework.encrypt.algorithm.Sha256Algorithm;
import com.duangframework.encrypt.exception.EncryptException;

import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

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
     * SHA1方式签名与WX一致
     * @param encryptDto    加密码对象
     * @param key   appkey
     * @param secret 安全码
     * @param timestamp 时间戳
     * @param nonce 随机字符串
     * @param encrypt 签名字符串
     * @return
     */
    public static String signSha1(EncryptDto encryptDto, String key, String secret, String timeStamp, String nonce) {
        String replyMsg = EncryptUtils.buildEncryptString(encryptDto);
        try {
            PKCS7Algorithm algorithm = new PKCS7Algorithm(key, secret, secret);
            // 加密
            String encrypt = algorithm.encrypt(nonce, replyMsg);
            return SHA1Algorithm.getSHA1(secret, timeStamp, nonce, encrypt);
        } catch (Exception e) {
            e.printStackTrace();
            throw new EncryptException(EncryptException.ValidateSignatureError);
        }
    }

    /**
     * 参数加密
     * @param encryptDto
     * @param key
     * @param secret
     * @param nonce
     * @return
     */
    public static String encrypt(EncryptDto encryptDto, String key, String secret,  String nonce) {
        String replyMsg = EncryptUtils.buildEncryptString(encryptDto);
//        PKCS7Algorithm algorithm = new PKCS7Algorithm(key, secret, secret);
        pkcs7Algorithm.setAppKey(key);
        pkcs7Algorithm.setAppSecret(secret.getBytes());
        pkcs7Algorithm.setReceiveid(secret);
        // 加密
        return pkcs7Algorithm.encrypt(nonce, replyMsg);
    }


}
