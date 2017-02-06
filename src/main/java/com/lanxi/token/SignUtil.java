package com.lanxi.token;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;


public class SignUtil {
	// --------------------------------baseStart-------------------------------------------
	/**
	 * md5摘要算法
	 * 
	 * @param src
	 *            明文字节码
	 * @return
	 */
	public static byte[] md5En(byte[] src) {
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			byte[] bytes = md5.digest(src);
			return bytes;
		} catch (Exception e) {
			throw new RuntimeException("md5摘要算法异常", e);
		}
	}

	/**
	 * md5摘要算法 补0
	 * 
	 * @param src
	 * @return
	 * @throws RuntimeException
	 */
	public static String md5LowerCase(String src, String charset) {

		try {
			if (src == null || src.length() < 1)
				throw new RuntimeException("md5摘要时,明文信息为null或为空");
			byte b[] = md5En(src.getBytes(charset));
			int i;
			StringBuffer buf = new StringBuffer("");
			for (int offset = 0; offset < b.length; offset++) {
				i = b[offset];
				if (i < 0)
					i += 256;
				if (i < 16)
					buf.append("0");
				buf.append(Integer.toHexString(i));
			}
			return buf.toString();// 32位的加密
		} catch (Exception e) {
			throw new RuntimeException("md5摘要算法异常", e);
		}
	}

	/**
	 * SHA-1摘要算法
	 * 
	 * @param src
	 *            明文字节
	 * @return
	 */
	public static byte[] sha1En(byte[] src) {
		try {
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
			return sha1.digest(src);
		} catch (Exception e) {
			throw new RuntimeException("sha1摘要异常", e);
		}
	}

	/**
	 * SHA-1加密
	 * 
	 * @param src
	 *            明文
	 * @param charset
	 *            字符集
	 * @return
	 */
	public static String sha1En(String src, String charset) {
		try {
			byte[] bytes = sha1En(src.getBytes(charset));
			return byteToHex(bytes);
		} catch (Exception e) {
			throw new RuntimeException("sha1摘要异常", e);
		}
	}

	/**
	 * base64加密
	 * 
	 * @param src
	 *            明文
	 * @param charset
	 *            字符集
	 * @return
	 */
	public static String base64En(String src, String charset) {
		try {
			if (src == null || src.length() < 1)
				throw new RuntimeException("bas64加密时,明文信息为null或为空");
			byte[] bytes = base64En(src.getBytes(charset));
			return new String(bytes, charset);
		} catch (Exception e) {
			throw new RuntimeException("bas64加密异常", e);
		}
	}

	/**
	 * base64加密
	 * 
	 * @param src
	 *            明文字节
	 * @return
	 */
	public static byte[] base64En(byte[] src) {
		try {
			if (src == null || src.length < 1)
				throw new RuntimeException("bas64加密时,明文信息为null或为空");
			byte[] bytes = Base64.encodeBase64(src);
			return bytes;
		} catch (Exception e) {
			throw new RuntimeException("bas64加密异常", e);
		}
	}

	/**
	 * base64解密
	 * 
	 * @param src
	 *            明文
	 * @param charset
	 *            字符集
	 * @return
	 */
	public static String base64De(String src, String charset) {
		try {
			if (src == null || src.length() < 1)
				throw new RuntimeException("bas64解密时,明文信息为null或为空");
			byte[] bytes = base64De(src.getBytes(charset));
			return new String(bytes, charset);
		} catch (Exception e) {
			throw new RuntimeException("bas64解密异常", e);
		}
	}

	/**
	 * base64解密
	 * 
	 * @param src
	 *            明文字节
	 * @return
	 */
	public static byte[] base64De(byte[] src) {
		try {
			if (src == null || src.length < 1)
				throw new RuntimeException("bas64解密时,明文信息为null或为空");
			byte[] bytes = Base64.decodeBase64(src);
			System.out.println("base64 ");
			System.out.println(bytes);
			return bytes;
		} catch (Exception e) {
			throw new RuntimeException("bas64解密异常", e);
		}
	}

	/**
	 * byte数组转hex字符串
	 * 
	 * @param bytes
	 * @return
	 */
	public static String byteToHex(byte[] bytes) {
		try {
			if (bytes == null || bytes.length < 1)
				throw new RuntimeException("byte转Hex时,byte数组为null或为空");
			return new String(Hex.encodeHex(bytes));
		} catch (Exception e) {
			throw new RuntimeException("byte转hex时异常", e);
		}
	}

	// ------------------------------------baseEnd--------------------------------------------

	// ------------------------------------signStart------------------------------------------
	/**
	 * map转String key=value&key2=value2 不排序 无签名
	 * 
	 * @param map
	 * @return
	 */
	public static String mapToStringNoSign(Map<String, String> map) {
		StringBuffer rs = new StringBuffer();
		for (Map.Entry<String, String> each : map.entrySet()) {
			if (each.getKey().equals("sign"))
				continue;
			rs.append(each.getKey());
			rs.append("=");
			rs.append(each.getValue());
			rs.append("&");
		}
		return rs.toString().substring(0, rs.length() - 1);
	}

	/**
	 * map转String key=value&key2=value2 不排序 有签名
	 * 
	 * @param map
	 * @return
	 */
	public static String mapToString(Map<String, String> map) {
		StringBuffer rs = new StringBuffer();
		for (Map.Entry<String, String> each : map.entrySet()) {
			rs.append(each.getKey());
			rs.append("=");
			rs.append(each.getValue());
			rs.append("&");
		}
		return rs.toString().substring(0, rs.length() - 1);
	}

	/**
	 * map转String key=value&key2=value2 key按字典排序 无签名
	 * 
	 * @param map
	 * @return
	 */
	public static String mapSortToStringNoSign(Map<String, String> map) {
		List<String> list = new ArrayList<String>(map.keySet());
		Collections.sort(list);
		StringBuffer rs = new StringBuffer();
		for (String each : list) {
			if (each.equals("sign"))
				continue;
			rs.append(each);
			rs.append("=");
			rs.append(map.get(each));
			rs.append("&");
		}
		return rs.toString().substring(0, rs.length() - 1);
	}

	/**
	 * map转String key=value&key2=value2 key按字典排序 有签名
	 * 
	 * @param map
	 * @return
	 */
	public static String mapSortToString(Map<String, String> map) {
		List<String> list = new ArrayList<String>(map.keySet());
		Collections.sort(list);
		StringBuffer rs = new StringBuffer();
		for (String each : list) {
			rs.append(each);
			rs.append("=");
			rs.append(map.get(each));
			rs.append("&");
		}
		return rs.toString().substring(0, rs.length() - 1);
	}

	/**
	 * map转String 仅仅返回key拼接成的字符串
	 * 
	 * @param map
	 * @return
	 */
	public static String mapToKeyString(Map<String, String> map) {
		List<String> list = new ArrayList<String>(map.keySet());
		StringBuffer rs = new StringBuffer();
		for (String each : list) {
			if (each.equals("sign"))
				continue;
			rs.append(each);
		}
		return rs.toString();
	}

	/**
	 * map转String 仅仅返回value拼接成的字符串
	 * 
	 * @param map
	 * @return
	 */
	public static String mapToValueString(Map<String, String> map) {
		StringBuffer rs = new StringBuffer();
		for (Map.Entry<String, String> each : map.entrySet()) {
			if (each.getKey().equals("sign"))
				continue;
			rs.append(each.getValue());
		}
		return rs.toString();
	}

	// ------------------------------------RSA--------------------------------------------
	/**
	 * 生成 rsa密钥对以map形式返回 public:公钥 private:私钥
	 * 
	 * @return
	 */
	public static Map<String, Object> getKeyPair() {
		try {
			Map<String, Object> map = new HashMap<String, Object>();
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair keyPair = generator.generateKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
			map.put("public", publicKey);
			map.put("private", privateKey);
			return map;
		} catch (Exception e) {
			throw new RuntimeException("获取密钥对异常", e);
		}
	}

	/**
	 * 获取公钥字符串
	 * 
	 * @param map
	 * @return
	 */
	public static String getPublicKey(Map<String, Object> map) {
		try {
			Key pubKey = (Key) map.get("public");
			return getKeyString(pubKey);
		} catch (Exception e) {
			throw new RuntimeException("获取公钥异常", e);
		}
	}

	/**
	 * 获取密钥字符串
	 * 
	 * @param key
	 * @return
	 */
	public static String getKeyString(Key key) {
		try {
			return Base64.encodeBase64String(key.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException("获取密钥字符串异常", e);
		}
	}

	/**
	 * 获取私钥字符串
	 * 
	 * @param map
	 * @return
	 */
	public static String getPrivateKey(Map<String, Object> map) {
		try {
			Key priKey = (Key) map.get("private");
			return Base64.encodeBase64String(priKey.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException("获取公钥异常", e);
		}
	}

	/**
	 * 将公钥字符串转为公钥对象
	 * 
	 * @param key
	 * @return
	 */
	public static PublicKey getPublicKey(String key) {
		try {
			byte[] keyBytes = (Base64.decodeBase64(key));
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 将私钥字符串转为私钥对象
	 * 
	 * @param key
	 * @return
	 */
	public static PrivateKey getPrivateKey(String key) {
		try {
			byte[] keyBytes = (Base64.decodeBase64(key));
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * rsa公钥加密
	 * 
	 * @param key
	 * @param content
	 * @return
	 */
	public static byte[] rsaEn(PublicKey key, byte[] content) {
		try {
			if (content.length > key.getEncoded().length - 11)
				throw new RuntimeException("加密内容过长,不能大于245个字节");
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] rs=cipher.doFinal(content);
			return rs;
		} catch (Exception e) {
			throw new RuntimeException("rsa加密异常", e);
		}
	}

	/**
	 * rsa公钥加密
	 * 
	 * @param pubKey
	 * @param content
	 * @return
	 */
	public static byte[] rsaEn(String pubKey, byte[] content) {
		PublicKey key = getPublicKey(pubKey);
		return rsaEn(key, content);
	}

//	/**
//	 * rsa公钥加密
//	 * 
//	 * @param pubKey
//	 * @param content
//	 * @param charset
//	 * @return
//	 */
//	public static byte[] rsaEn(String pubKey, String conntent, String charset) {
//		try {
//			PublicKey key = getPublicKey(pubKey);
//			byte[] bytes = conntent.getBytes(charset);
//			return rsaEn(key, bytes);
//		} catch (Exception e) {
//			throw new RuntimeException("字符串转字节时编码异常", e);
//		}
//	}

	/**
	 * rsa 私钥解密
	 * 
	 * @param key
	 * @param content
	 * @return
	 */
	public static byte[] rsaDe(PrivateKey key, byte[] content) {
		try {
			if (content.length > key.getEncoded().length)
				throw new RuntimeException("解密内容过长");
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(content);
		} catch (Exception e) {
			throw new RuntimeException("rsa解密异常", e);
		}
	}

	/**
	 * rsa 私钥解密
	 * 
	 * @param priKey
	 * @param content
	 * @return
	 */
	public static byte[] rsaDe(String priKey, byte[] content) {
		PrivateKey key = getPrivateKey(priKey);
		return rsaDe(key, content);
	}

//	/**
//	 * rsa 私钥解密
//	 * 
//	 * @param priKey
//	 * @param content
//	 * @param charset
//	 * @return
//	 */
//	public static byte[] rsaDe(String priKey, String content, String charset) {
//		try {
//			PrivateKey key = getPrivateKey(priKey);
//			byte[] bytes = content.getBytes(charset);
//			return rsaDe(key, bytes);
//		} catch (Exception e) {
//			throw new RuntimeException("字符串转字节时编码异常", e);
//		}
//	}

	/**
	 * rsa md5 获取签名
	 * 
	 * @param key
	 * @param content
	 */
	public static String rsaMd5Sign(PrivateKey key, byte[] content) {
		try {
			Signature sign = Signature.getInstance("MD5WithRSA");
			sign.initSign(key);
			sign.update(content);
			return Base64.encodeBase64String(sign.sign());
		} catch (Exception e) {
			throw new RuntimeException("获取rsaMd5签名异常", e);
		}
	}
	/**
	 * rsa md5 获取签名
	 * 
	 * @param priKey
	 *            私钥字符串
	 * @param data
	 *            数据
	 * @return 签名
	 */
	public static String rsaMd5Sign(String priKey, byte[] data) {
		try {
			PrivateKey key = getPrivateKey(priKey);
			return rsaMd5Sign(key, data);
		} catch (Exception e) {
			throw new RuntimeException("字符串转字节是编码异常", e);
		}
	}
//	/**
//	 * rsa md5 获取签名
//	 * 
//	 * @param priKey
//	 * @param content
//	 * @param charset
//	 * @return
//	 */
//	public static String rsaMd5Sign(String priKey, String content, String charset) {
//		try {
//			PrivateKey key = getPrivateKey(priKey);
//			byte[] bytes = content.getBytes(charset);
//			return rsaMd5Sign(key, bytes);
//		} catch (Exception e) {
//			throw new RuntimeException("字符串转字节是编码异常", e);
//		}
//	}
	// ---------------------------------------des----------------------------------------------
	/**
	 * des加密
	 * 
	 * @param key
	 *            密钥
	 * @param data
	 *            数据
	 * @return 加密后的数据
	 */
	public static byte[] desEn(String key, byte[] data) {
		try {
			SecureRandom random = new SecureRandom();
			DESKeySpec desKey = new DESKeySpec(key.getBytes("utf-8"));
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey secretKey = keyFactory.generateSecret(desKey);
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, random);
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException("des加密异常", e);
		}
	}

	/**
	 * des解密
	 * 
	 * @param key
	 *            密钥
	 * @param data
	 *            数据
	 * @return
	 */
	public static byte[] desDe(String key, byte[] data) {
		try {
			SecureRandom random = new SecureRandom();
			DESKeySpec desKey = new DESKeySpec(key.getBytes("utf-8"));
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			SecretKey secretKey = keyFactory.generateSecret(desKey);
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, random);
			System.err.println(cipher);
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException("des解密异常", e);
		}
	}
}
