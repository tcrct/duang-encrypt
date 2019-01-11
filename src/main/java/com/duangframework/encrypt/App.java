package com.duangframework.encrypt;

import com.duangframework.encrypt.core.EncryptFactory;
import com.duangframework.encrypt.core.EncryptType;
import com.duangframework.encrypt.core.EncryptUtils;

import java.security.PublicKey;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args )
    {
        PublicKey publicKey = EncryptUtils.getPublicKey(null, EncryptType.PKCS7.name());
        System.out.println(publicKey.getFormat());
//        System.out.println(EncryptUtils.getPublicKey(null, EncryptType.PKCS7.name()));

    }
}
