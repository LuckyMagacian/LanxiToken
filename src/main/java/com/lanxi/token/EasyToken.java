package com.lanxi.token;

import java.util.Map;

import com.alibaba.fastjson.JSONObject;

/**
 * 自包含令牌
 * @author 1
 *步骤
 *	对象->json->负载串->签名->token
 */
public class EasyToken extends Token { 
	/**哈希码*/
	private Integer hash;
	/**负载串*/
	private String  payStr;
	/**私钥*/
	private static final String priKey;
	/**公钥*/
	public  static final String pubKey;
	/**手动设置的私钥*/
	private static  	 String key=null;
	/**生成密钥对*/
	static{
		Map<String, Object> map=SignUtil.getKeyPair();
		priKey=SignUtil.getPrivateKey(map);
		pubKey=SignUtil.getPublicKey(map);
	}
	/**自定义的信息*/
	private String info;
//	/**签名*/
//	private String sign;
	
	public String getInfo() {
		return info;
	}
	public void setInfo(String info) {
		this.info = info;
	}
	
//	private void setSign(String sign){
//		this.sign=sign;
//	}
	
	public String sign() {
		return SignUtil.md5LowerCase(toJson(),"utf-8");
	}
	@Override
	public String toString() {
		return toJson();
	}
	/**
	 * 获取json串
	 * @return
	 */
	public String toJson(){
		return JSONObject.toJSONString(this);
	}
	/**
	 * 获取负载串
	 * @return
	 */
	public String toPayload(){
		if(hash==null||hash!=this.hashCode()){
			hash=this.hashCode();
			payStr=new String(SignUtil.base64En(SignUtil.desEn(key==null?priKey:key, toJson().getBytes())));
		}
		return payStr;
	}
	/**
	 * 获取token串
	 */
	public String toToken(){
		String str=toPayload()+"."+sign();
//		byte[] bytes=SignUtil.desEn(priKey, str.getBytes());
//		return new String(SignUtil.base64En(bytes));
		return str;
	}
	/**
	 * 将token串解析成tokenStr对象
	 * @param tokenstr
	 * @return
	 */
	@SuppressWarnings("finally")
	public static EasyToken flipToken(String tokenstr){
		if(tokenstr==null)
			return null;
		EasyToken token=null;
		System.out.println(token);
		try{
//			byte[] bytes=SignUtil.base64De(tokenstr.getBytes("utf-8"));
//			byte[] bytes2=SignUtil.desDe(priKey,bytes);
//			String str=new String(bytes2);
			String[] strs=tokenstr.split("\\.");
			System.out.println(strs);
			
			if(key==null){
				 key=priKey;
			}
			System.out.println(key);
			byte[] bytes=SignUtil.desDe(key==null?priKey:key,SignUtil.base64De(strs[0].getBytes()));
			System.err.println(bytes);
			String jStr=new String(bytes);
			System.out.println(jStr);
			token=JSONObject.parseObject(jStr, EasyToken.class);
			System.out.println(token);
			String sign=SignUtil.md5LowerCase(token.toJson(),"utf-8");
			System.out.println(sign);
			if(!sign.equals(strs[1]))
				return null;
			return token;
		}catch (Exception e) {
			throw new RuntimeException("token串解析异常",e);
		}
	}
	/**
	 * 校验令牌
	 * 
	 * @param token
	 * @return
	 */
	public static boolean verifyToken(EasyToken token) {
		Long now = System.currentTimeMillis();
		if (now<(token.getValidTo()))
			return true;
		return false;
	}

	/**
	 * 校验令牌
	 * 
	 * @param tokenStr
	 * @return
	 */
	public static boolean verifyToken(String tokenStr) {
		EasyToken token = flipToken(tokenStr);
		if (token == null)
			return false;
		return verifyToken(token);
	}
	/**
	 * 校验令牌及其携带的信息
	 * 
	 * @param tokenStr
	 * @param otherInfo
	 * @return
	 */
	public static boolean verifyToken(String tokenStr,String otherInfo){
		EasyToken token = flipToken(tokenStr);
		if (token == null)
			return false;
		if (!token.getInfo().equals(otherInfo))
			return false;
		return verifyToken(token);
	}
	/**
	 * 校验token
	 * 若token剩余时间小于20%  重置token有效期(续费)
	 * @param tokenStr
	 * @return
	 */
	public static EasyToken verifyTokenRenew(String tokenStr){
		EasyToken token = flipToken(tokenStr);
		if(token!=null){
			Long iat=token.getValidFrom();
			Long exp=token.getValidTo();
			Long now=System.currentTimeMillis();
			if(verifyToken(token)){
				if((exp-now)/(double)(exp-iat)<0.2){
					token.setValidFrom(now);
					token.setValidTo(now+(exp-iat));
				}
			}else{
			token=null;
			}
		}
		return token;
	}
	/**
	 * 校验token及其内容
	 * 若token剩余时间小于20%  重置token有效期(续费)
	 * @param tokenStr
	 * @return
	 */
	public static EasyToken verifyTokenRenew(String tokenStr,String otherInfo){
		EasyToken token=verifyTokenRenew(tokenStr);
		return token==null?null:token.getInfo().equals(otherInfo)?token:null;
	}
	/**
	 * 手动设置私钥
	 * @param key
	 * @return
	 */
	public static boolean setPrivateKey(String prikey){
		System.out.println("手动设置私钥:"+key);
		key=prikey;
		return true;
	}
}
