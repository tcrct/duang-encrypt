package com.duangframework.encrypt.algorithm;

import com.duangframework.encrypt.core.Base64Utils;
import com.duangframework.encrypt.exception.EncryptException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.SecureRandom;

/**
 * 提供基于PKCS7算法的加解密接口.
 */
public class PKCS7Algorithm {
	private static Charset CHARSET = Charset.forName("utf-8");
	private static int BLOCK_SIZE = 32;
	private byte[] symmetricKey;

	public PKCS7Algorithm() {

	}

    public void setSymmetricKey(String symmetricKey) {
        this.symmetricKey = Base64Utils.decodeBase64(symmetricKey);
    }

    /**
     *
     * @param symmetricKey      密钥
     * @throws EncryptException
     */
    public PKCS7Algorithm(String symmetricKey) throws EncryptException {
        this.symmetricKey = Base64Utils.decodeBase64(symmetricKey);
    }


	/**
	 * AES加密字符串，对明文加密
	 *
	 * @param content
	 *            需要被加密的字符串
	 * @return 密文
	 */
	public String encrypt(String content) {
		try {
			// 创建AES的Key生产者
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			// 利用用户密码作为随机数初始化出
			kgen.init(128, new SecureRandom(symmetricKey));
			// 128位的key生产者
			//加密没关系，SecureRandom是生成安全随机数序列，password.getBytes()是种子，只要种子相同，序列就一样，所以解密只要有password就行
			// 根据用户密码，生成一个密钥
			SecretKey secretKey = kgen.generateKey();
			// 返回基本编码格式的密钥，如果此密钥不支持编码，则返回null。
			byte[] enCodeFormat = secretKey.getEncoded();
			// 转换为AES专用密钥
			SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
			// 创建密码器
			Cipher cipher = Cipher.getInstance("AES");
			byte[] byteContent = content.getBytes(CHARSET);
			// 初始化为加密模式的密码器
			cipher.init(Cipher.ENCRYPT_MODE, key);
			// 加密
			byte[] result = cipher.doFinal(byteContent);
			// 使用BASE64对加密后的字符串进行编码
			return Base64Utils.encode(result);
		} catch (Exception e) {
			throw new EncryptException(EncryptException.IllegalAesKey);
		}
	}


	/**
	 * 解密AES加密过的字符串，密文变明文
	 *
	 * @param content
	 *            AES加密过过的内容
	 * @return 明文
	 */
	public String decrypt(String content) {
		try {
			byte[] resultByte = Base64Utils.decodeBase64(content);
			KeyGenerator kgen = KeyGenerator.getInstance("AES");// 创建AES的Key生产者
			kgen.init(128, new SecureRandom(symmetricKey));
			SecretKey secretKey = kgen.generateKey();// 根据用户密码，生成一个密钥
			byte[] enCodeFormat = secretKey.getEncoded();// 返回基本编码格式的密钥
			SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");// 转换为AES专用密钥
			Cipher cipher = Cipher.getInstance("AES");// 创建密码器
			cipher.init(Cipher.DECRYPT_MODE, key);// 初始化为解密模式的密码器
			byte[] result = cipher.doFinal(resultByte);
			return null != result ? new String(result, CHARSET) : ""; // 明文
		} catch (Exception e) {
			throw new EncryptException(EncryptException.IllegalAesKey);
		}
	}


//
//
//
//
//	/**
//	 * 对明文进行加密.
//	 *
//	 * @param text 需要加密的明文
//	 * @return 加密后base64编码的字符串
//	 * @throws EncryptException aes加密失败
//	 */
//	public String encrypt(String randomStr, String text) throws EncryptException {
//		ByteGroup byteCollector = new ByteGroup();
//		byte[] randomStrBytes = randomStr.getBytes(CHARSET);
//		byte[] textBytes = text.getBytes(CHARSET);
//		byte[] networkBytesOrder = EncryptUtils.getNetworkBytesOrder(textBytes.length);
//		byte[] receiveidBytes = receiveid.getBytes(CHARSET);
//
//		// randomStr + networkBytesOrder + text + receiveid
//		byteCollector.addBytes(randomStrBytes);
//		byteCollector.addBytes(networkBytesOrder);
//		byteCollector.addBytes(textBytes);
//		byteCollector.addBytes(receiveidBytes);
//
//		// ... + pad: 使用自定义的填充方式对明文进行补位填充
//		byte[] padBytes = encode(byteCollector.size());
//		byteCollector.addBytes(padBytes);
//
//		// 获得最终的字节流, 未加密
//		byte[] unencrypted = byteCollector.toBytes();
//
//		try {
//			// 设置加密模式为AES的CBC模式
//			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
//			SecretKeySpec keySpec = new SecretKeySpec(appSecret, "AES");
//			IvParameterSpec iv = new IvParameterSpec(appSecret, 0, 16);
//			cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
//
//			// 加密
//			byte[] encrypted = cipher.doFinal(unencrypted);
//
//			// 使用BASE64对加密后的字符串进行编码
//			String base64Encrypted = Base64.encode(encrypted);
//
//			return base64Encrypted;
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new EncryptException(EncryptException.EncryptAESError);
//		}
//	}
//
//	/**
//	 * 获得对明文进行补位填充的字节.
//	 *
//	 * @param count 需要进行填充补位操作的明文字节个数
//	 * @return 补齐用的字节数组
//	 */
//	private byte[] encode(int count) {
//		// 计算需要填充的位数
//		int amountToPad = BLOCK_SIZE - (count % BLOCK_SIZE);
//		if (amountToPad == 0) {
//			amountToPad = BLOCK_SIZE;
//		}
//		// 获得补位所用的字符
//		char padChr = chr(amountToPad);
//		String tmp = new String();
//		for (int index = 0; index < amountToPad; index++) {
//			tmp += padChr;
//		}
//		return tmp.getBytes(CHARSET);
//	}
//
//	/**
//	 * 删除解密后明文的补位字符
//	 *
//	 * @param decrypted 解密后的明文
//	 * @return 删除补位字符后的明文
//	 */
//	private byte[] decode(byte[] decrypted) {
//		int pad = (int) decrypted[decrypted.length - 1];
//		if (pad < 1 || pad > 32) {
//			pad = 0;
//		}
//		return Arrays.copyOfRange(decrypted, 0, decrypted.length - pad);
//	}
//
//	/**
//	 * 将数字转化成ASCII码对应的字符，用于对明文进行补码
//	 *
//	 * @param a 需要转化的数字
//	 * @return 转化得到的字符
//	 */
//	private char chr(int a) {
//		byte target = (byte) (a & 0xFF);
//		return (char) target;
//	}
//
//
//	/**
//	 * 将企业微信回复用户的消息加密打包.
//	 * <ol>
//	 * 	<li>对要发送的消息进行AES-CBC加密</li>
//	 * 	<li>生成安全签名</li>
//	 * 	<li>将消息密文和安全签名打包成xml格式</li>
//	 * </ol>
//	 *
//	 * @param nonce 随机串，可以自己生成，也可以用URL参数的nonce
//	 *
//	 * @return 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
//	 * @throws EncryptException 执行失败，请查看该异常的错误码和具体的错误信息
//	 */
//	public String encrypt(EncryptDto dto, String nonce) throws EncryptException {
//		String replyMsg = EncryptUtils.buildEncryptString(dto);
//		// 加密
//		String encrypt = encrypt(nonce, replyMsg);
//
//		return encrypt;
//	}

}
