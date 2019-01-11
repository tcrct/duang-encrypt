package com.duangframework.encrypt.core;

import com.duangframework.encrypt.algorithm.PKCS7Algorithm;
import com.duangframework.encrypt.algorithm.Pbkdf2Sha256Algorithm;
import com.duangframework.encrypt.algorithm.SHA1Algorithm;
import com.duangframework.encrypt.algorithm.Sha256Algorithm;
import com.duangframework.encrypt.exception.EncryptException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

/**
 * Created by laotang on 2019/1/1.
 */
public class EncryptUtils {

    private static final String FRAMEWORK_OWNER = "duang";
    private static final String RANDOM_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


    /**
     * 按uri(\n)->header(\n)->params顺序合成一个字符串，每一个以换行符\n分隔
     * @param encryptDto
     * @return
     */
    public static String buildEncryptString(EncryptDto encryptDto) {
        if(null == encryptDto) {
            throw new NullPointerException("encryptDto is null");
        }
        StringBuilder signStr = new StringBuilder();
        String lb = "\n";
        signStr.append(encryptDto.getUri()).append(lb);
        Map<String,String> headerParams = encryptDto.getHeaders();
        //如果有@"Accept"头，这个头需要参与签名
        if (headerParams.containsKey(HttpHeaderNames.ACCEPT)) {
            signStr.append(headerParams.get(HttpHeaderNames.ACCEPT)).append(lb);
        }
        //如果有@"Content-MD5"头，这个头需要参与签名
        if (headerParams.containsKey(HttpHeaderNames.CONTENT_MD5)) {
            signStr.append(headerParams.get(HttpHeaderNames.CONTENT_MD5)).append(lb);
        }
        //如果有@"Content-Type"头，这个头需要参与签名
        if (headerParams.containsKey(HttpHeaderNames.CONTENT_TYPE)) {
            signStr.append(headerParams.get(HttpHeaderNames.CONTENT_TYPE)).append(lb);
        }
        //签名优先读取HTTP_CA_HEADER_DATE，因为通过浏览器过来的请求不允许自定义Date（会被浏览器认为是篡改攻击）
        if (headerParams.containsKey(HttpHeaderNames.DATE)) {
            signStr.append(headerParams.get(HttpHeaderNames.DATE)).append(lb);
        }

        // Header部份
        Map<String,String> headerParamItemMap = new TreeMap<String,String>(headerParams);
        for(Iterator<Map.Entry<String,String>> iterator = headerParamItemMap.entrySet().iterator(); iterator.hasNext();) {
            Map.Entry<String,String> entry = iterator.next();
            if(entry.getKey().startsWith(FRAMEWORK_OWNER)) {
                signStr.append(entry.getValue()).append(lb);
            }
        }

        // Param部份
        Map<String, Object> paramsMap = encryptDto.getParams();
        if(null != paramsMap && paramsMap.isEmpty()) {
            Map<String, Object> parameters = new TreeMap<String, Object>(paramsMap);
            for(Iterator<Map.Entry<String,Object>> iterator = parameters.entrySet().iterator(); iterator.hasNext();) {
                Map.Entry<String,Object> entry = iterator.next();
                Object value = entry.getValue();
                if(null != value) {
                    signStr.append(entry.getKey()).append("=").append(value).append("&");
                }
            }
            if (signStr.toString().endsWith("&")) {
                signStr.deleteCharAt(signStr.length() - 1);
            }
        }
        return signStr.toString();
    }

    // 随机生成16位字符串
    public static String getRandomStr() {
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 16; i++) {
            int number = random.nextInt(RANDOM_STR.length());
            sb.append(RANDOM_STR.charAt(number));
        }
        return sb.toString();
    }

    // 生成4个字节的网络字节序
    public static byte[] getNetworkBytesOrder(int sourceNumber) {
        byte[] orderBytes = new byte[4];
        orderBytes[3] = (byte) (sourceNumber & 0xFF);
        orderBytes[2] = (byte) (sourceNumber >> 8 & 0xFF);
        orderBytes[1] = (byte) (sourceNumber >> 16 & 0xFF);
        orderBytes[0] = (byte) (sourceNumber >> 24 & 0xFF);
        return orderBytes;
    }

    /**
     * 密文加盐
     *
     * @return String
     */
    public static String getSalt() {
        int length = 12;
        Random rand = new Random();
        char[] rs = new char[length];
        for (int i = 0; i < length; i++) {
            int t = rand.nextInt(3);
            if (t == 0) {
                rs[i] = (char) (rand.nextInt(10) + 48);
            } else if (t == 1) {
                rs[i] = (char) (rand.nextInt(26) + 65);
            } else {
                rs[i] = (char) (rand.nextInt(26) + 97);
            }
        }
        return new String(rs);
    }

    public static PublicKey getPublicKey(byte[] keyBytes, String algorithm) {
        PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.err.println("Could not reconstruct the public key");
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) {
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.err.println("Could not reconstruct the private key");
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }

        return privateKey;
    }

}
