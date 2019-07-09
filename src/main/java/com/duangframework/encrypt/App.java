package com.duangframework.encrypt;

import com.duangframework.encrypt.core.EncryptDto;
import com.duangframework.encrypt.core.EncryptFactory;
import com.duangframework.encrypt.core.EncryptUtils;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args ) throws Exception
    {
//        PublicKey publicKey = EncryptUtils.getPublicKey(null, EncryptType.PKCS7.name());
//        System.out.println(publicKey.getFormat());
//        System.out.println(EncryptUtils.getPublicKey(null, EncryptType.PKCS7.name()));


        String replyMsg = "我是老唐";
        String secret = "AU4yUrUnT5UugrFIgruu7F5ng99Nn50p5AgtCZLu";
        String encyptString = EncryptFactory.encrypt(replyMsg, secret);
        System.out.println(encyptString);

        String deCodeString = EncryptUtils.validParams(encyptString,secret);
        System.out.println(deCodeString);
//
//        EncryptDto encryptDto = new EncryptDto();
//        EncryptUtils.buildEncryptString(encryptDto)
//
//
//        System.out.println(EncryptUtils.getAppSecret());

    }
}
