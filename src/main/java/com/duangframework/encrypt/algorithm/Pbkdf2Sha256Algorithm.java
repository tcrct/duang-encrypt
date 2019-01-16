package com.duangframework.encrypt.algorithm;

import com.duangframework.encrypt.core.Base64Utils;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * https://my.oschina.net/haopeng/blog/2873022
 * pbkdf2_sha256加密验证算法
 *
 *   用于密码加密
 *
 * @author  laotang
 * @since 1.6
 */
public class Pbkdf2Sha256Algorithm {

    //默认迭代计数为 20000
    private static final Integer DEFAULT_ITERATIONS = 100000;
    //算法名称
    private static final String algorithm = "pbkdf2_sha256";


    public Pbkdf2Sha256Algorithm() {

    }

    /**
     * 获取密文
     *
     * @param password   密码明文
     * @param salt       加盐
     * @param iterations 迭代计数
     * @return
     * @since 1.6
     */
    private String getEncodedHash(String password, String salt, int iterations) {
        // Returns only the last part of whole encoded password
        SecretKeyFactory keyFactory = null;
        try {
            keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Could NOT retrieve PBKDF2WithHmacSHA256 algorithm: " + e.getMessage());
        }
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, 256);
        SecretKey secret = null;
        try {
            secret = keyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            System.err.println("Could NOT generate secret key: " + e.getMessage());
        }
        byte[] rawHash = secret.getEncoded();
        return Base64Utils.encode(rawHash);
    }

    /**
     * iterations is default 20000
     *
     * @param password
     * @param salt
     * @return
     */
    public String encode(String password, String salt) {
        return encode(password, salt, DEFAULT_ITERATIONS);
    }

    /**
     * @param password   密码明文
     * @param salt       加盐
     * @param iterations 迭代计数
     * @return      算法名称$迭代计数$盐值$密文
     */
    public String encode(String password, String salt, int iterations) {
        // returns hashed password, along with algorithm, number of iterations and salt
        String hash = getEncodedHash(password, salt, iterations);
        return String.format("%s$%d$%s$%s", algorithm, iterations, salt, hash);
    }

    /**
     * 校验密码是否合法
     *
     * @param password       明文
     * @param hashedPassword 密文
     * @return
     */
    public boolean verification(String password, String hashedPassword) {
        // hashedPassword consist of: ALGORITHM, ITERATIONS_NUMBER, SALT and
        // HASH; parts are joined with dollar character ("$")
        String[] parts = hashedPassword.split("\\$");
        if (parts.length != 4) {
            // wrong hash format
            return false;
        }
        Integer iterations = Integer.parseInt(parts[1]);
        String salt = parts[2];
        String hash = encode(password, salt, iterations);
        return hash.equals(hashedPassword);
    }
}
