

import java.util.Date;

import com.lanxi.token.EasyToken;

public class TestEasyToken {

	public static void main(String[] args){
		String string="CC0wVOr04h4m7mj9NuuoLnc0UT5WcUoCTfSGyqnzM0d69lzGyzW7XbQq62TmGJ9+n+UsBU5JzesbeoDyS/9uwM/nCvk+4JL1tZpXSFK9mBsLst3CPMfCQ9lfsqjWxv6s.ada588a17157f56d50cb28aca9831798";
		System.out.println(EasyToken.flipToken(string));
		string="1485276806518"; 
		System.out.println(new Date(Long.parseLong(string)));
	}
}
