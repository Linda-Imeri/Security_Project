package security;

public class Ceasar {
	public static String encrypt(int key, String plaintext) {
		if(key>26) 
			{ key=key%26;}
		else if (key<0) 
			{ key=(key%26)+26; }
		String cipherText=" ";
		int length=plaintext.length();
		for(int i=0;i<length;i++) {
			char ch=plaintext.charAt(i);
			if(Character.isLetter(ch)) {
				if(Character.isLowerCase(ch)) {
					char c=(char)(ch+key);
					if(c>'z') {
						cipherText+=(char)(ch-(26-key));
					}
					else {
						cipherText+=c;
					}
				}
				else if(Character.isUpperCase(ch)) {
					char c=(char)(ch+key);
					if(c>'Z') {
						cipherText+=(char)(ch-(26-key));
					}
					else {
						cipherText+=c;
					}
				}
				
			}
			else {
				cipherText+=ch;
			}
		}
		
		return cipherText;
	}
		
	
	public static String decrypt(int key, String encryptedText) {
		
		if(key>26) 
		{ key=key%26;}
	else if (key<0) 
		{ key=(key%26)+26; }
	String cipherText=" ";
	int length=encryptedText.length();
	for(int i=0;i<length;i++) {
		char ch=encryptedText.charAt(i);
		if(Character.isLetter(ch)) {
			if(Character.isLowerCase(ch)) {
				char c=(char)(ch-key);
				if(c<'a') {
					cipherText+=(char)(ch+(26-key));
				}
				else {
					cipherText+=c;
				}
			}
			else if(Character.isUpperCase(ch)) {
				char c=(char)(ch-key);
				if(c<'A') {
					cipherText+=(char)(ch+(26-key));
				}
				else {
					cipherText+=c;
				}
			}
			
		}
		else {
			cipherText+=ch;
		}
	}
	
	return cipherText;
	}
	}