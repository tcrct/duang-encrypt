package com.duangframework.encrypt.core;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.Charset;

/**
 * JDK6 Base64工具
 */
public class Base64Utils {

    private Base64Utils() {}

    /**
     * 编码
     * @param value byte数组
     * @return {String}
     */
    public static String encode(byte[] value) {
        return DatatypeConverter.printBase64Binary(value);
    }

    /**
     * 编码
     * @param value 字符串
     * @return {String}
     */
    public static String encode(String value) {
        byte[] val = value.getBytes(Charset.forName("UTF-8"));
        return Base64Utils.encode(val);
    }

    /**
     * 编码
     * @param value 字符串
     * @param charsetName charSet
     * @return {String}
     */
    public static String encode(String value, String charsetName) {
        byte[] val = value.getBytes(Charset.forName(charsetName));
        return Base64Utils.encode(val);
    }

    /**
     * 解码
     * @param value 字符串
     * @return {byte[]}
     */
    public static byte[] decodeBase64(String value) {
        return DatatypeConverter.parseBase64Binary(value);
    }

    /**
     * 解码
     * @param value 字符串
     * @return {String}
     */
    public static String decode(String value) {
        byte[] decodedValue = Base64Utils.decodeBase64(value);
        return new String(decodedValue, Charset.forName("UTF-8"));
    }

    /**
     * 解码
     * @param value 字符串
     * @param charsetName 字符集
     * @return {String}
     */
    public static String decode(String value, String charsetName) {
        byte[] decodedValue = Base64Utils.decodeBase64(value);
        return new String(decodedValue, Charset.forName(charsetName));
    }

}
