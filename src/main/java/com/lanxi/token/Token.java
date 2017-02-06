package com.lanxi.token;

public abstract class Token { 
	/**生成时间*/
	private Long 	validFrom;
	/**过期时间*/
	private Long	validTo;
//	/**发布者*/
//	private String	issuer;
//	/**请求者*/
//	private	String	subject;
	
	public Token(){
		validFrom=System.currentTimeMillis();
	}
	public void setValidFrom(Long validFrom) {
		this.validFrom = validFrom;
	}
	public Long getValidFrom() {
		return validFrom;
	}
	public Long getValidTo() {
		return validTo;
	}
	public void setValidTo(Long validTo) {
		this.validTo = validTo;
	}
//	public String getIssuer() {
//		return issuer;
//	}
//	public void setIssuer(String issuer) {
//		this.issuer = issuer;
//	}
//	public String getSubject() {
//		return subject;
//	}
//	public void setSubject(String subject) {
//		this.subject = subject;
//	}
	@Override
	public String toString() {
		return "Token [validFrom=" + validFrom + ", validTo=" + validTo 
				+ "]";
	}
	
	public abstract String toToken();
}
