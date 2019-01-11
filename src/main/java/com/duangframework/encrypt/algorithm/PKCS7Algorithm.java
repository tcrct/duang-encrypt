/**
 * 对企业微信发送给企业后台的消息加解密示例代码.
 *
 * @copyright Copyright (c) 1998-2014 Tencent Inc.
 */

// ------------------------------------------------------------------------

package com.duangframework.encrypt.algorithm;

import com.duangframework.encrypt.core.*;
import com.duangframework.encrypt.exception.EncryptException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * 提供基于PKCS7算法的加解密接口.
 */
public class PKCS7Algorithm {
	private static Charset CHARSET = Charset.forName("utf-8");
	private static int BLOCK_SIZE = 32;
	private String receiveid;
	private byte[] appSecret;
	private String appKey;

	public PKCS7Algorithm() {

	}

	public PKCS7Algorithm(String appKey, String appSecret, String receiveid) throws EncryptException {
		if (appSecret.length() != 43) {
			throw new EncryptException(EncryptException.IllegalAesKey);
		}
		this.appSecret = Base64.decode(appSecret + "=");
		this.receiveid = receiveid;
		this.appKey = appKey;
	}

	public void setReceiveid(String receiveid) {
		this.receiveid = receiveid;
	}

	public void setAppSecret(byte[] appSecret) {
		this.appSecret = appSecret;
	}

	public void setAppKey(String appKey) {
		this.appKey = appKey;
	}


	/**
	 * 对明文进行加密.
	 *
	 * @param text 需要加密的明文
	 * @return 加密后base64编码的字符串
	 * @throws EncryptException aes加密失败
	 */
	public String encrypt(String randomStr, String text) throws EncryptException {
		ByteGroup byteCollector = new ByteGroup();
		byte[] randomStrBytes = randomStr.getBytes(CHARSET);
		byte[] textBytes = text.getBytes(CHARSET);
		byte[] networkBytesOrder = EncryptUtils.getNetworkBytesOrder(textBytes.length);
		byte[] receiveidBytes = receiveid.getBytes(CHARSET);

		// randomStr + networkBytesOrder + text + receiveid
		byteCollector.addBytes(randomStrBytes);
		byteCollector.addBytes(networkBytesOrder);
		byteCollector.addBytes(textBytes);
		byteCollector.addBytes(receiveidBytes);

		// ... + pad: 使用自定义的填充方式对明文进行补位填充
		byte[] padBytes = encode(byteCollector.size());
		byteCollector.addBytes(padBytes);

		// 获得最终的字节流, 未加密
		byte[] unencrypted = byteCollector.toBytes();

		try {
			// 设置加密模式为AES的CBC模式
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(appSecret, "AES");
			IvParameterSpec iv = new IvParameterSpec(appSecret, 0, 16);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

			// 加密
			byte[] encrypted = cipher.doFinal(unencrypted);

			// 使用BASE64对加密后的字符串进行编码
			String base64Encrypted = Base64.encode(encrypted);

			return base64Encrypted;
		} catch (Exception e) {
			e.printStackTrace();
			throw new EncryptException(EncryptException.EncryptAESError);
		}
	}

	/**
	 * 获得对明文进行补位填充的字节.
	 *
	 * @param count 需要进行填充补位操作的明文字节个数
	 * @return 补齐用的字节数组
	 */
	private byte[] encode(int count) {
		// 计算需要填充的位数
		int amountToPad = BLOCK_SIZE - (count % BLOCK_SIZE);
		if (amountToPad == 0) {
			amountToPad = BLOCK_SIZE;
		}
		// 获得补位所用的字符
		char padChr = chr(amountToPad);
		String tmp = new String();
		for (int index = 0; index < amountToPad; index++) {
			tmp += padChr;
		}
		return tmp.getBytes(CHARSET);
	}

	/**
	 * 删除解密后明文的补位字符
	 *
	 * @param decrypted 解密后的明文
	 * @return 删除补位字符后的明文
	 */
	private byte[] decode(byte[] decrypted) {
		int pad = (int) decrypted[decrypted.length - 1];
		if (pad < 1 || pad > 32) {
			pad = 0;
		}
		return Arrays.copyOfRange(decrypted, 0, decrypted.length - pad);
	}

	/**
	 * 将数字转化成ASCII码对应的字符，用于对明文进行补码
	 *
	 * @param a 需要转化的数字
	 * @return 转化得到的字符
	 */
	private char chr(int a) {
		byte target = (byte) (a & 0xFF);
		return (char) target;
	}


	/**
	 * 将企业微信回复用户的消息加密打包.
	 * <ol>
	 * 	<li>对要发送的消息进行AES-CBC加密</li>
	 * 	<li>生成安全签名</li>
	 * 	<li>将消息密文和安全签名打包成xml格式</li>
	 * </ol>
	 *
	 * @param nonce 随机串，可以自己生成，也可以用URL参数的nonce
	 *
	 * @return 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
	 * @throws EncryptException 执行失败，请查看该异常的错误码和具体的错误信息
	 */
	public String encrypt(EncryptDto dto, String nonce) throws EncryptException {
		String replyMsg = EncryptUtils.buildEncryptString(dto);
		// 加密
		String encrypt = encrypt(nonce, replyMsg);

		return encrypt;
	}

}
