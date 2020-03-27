package security;



public class Numerical {
	public static String encrypt( String plaintext) {
		
		String encryptedtext = "";
		
		char [] ch=new char[plaintext.length()];
		
		
		for (int i = 0; i < plaintext.length(); ++i) {
			
			ch[i] = plaintext.charAt(i); 
			char character=ch[i];
			if(Character.isDigit(character))
			{
				encryptedtext="Error , you have typed a number";
				break;
				
				
			}
			
		    else if(Character.isLetter(character)) {
		    	
		    	int n = (int)character - (int)'a' + 1;
		    	encryptedtext += String.valueOf(n)+" ";
		    }
			
		    else if(character==' ') {
		    	encryptedtext += " ";
		    }
			
		    else{
		    	encryptedtext =" Error, you have entered invalid value";
		    	break;
		    };
	
		
		}
		
		return  encryptedtext ;
		
	}
	
	
	
	
	
	public static String decrypt(String encryptedText) {
		String decryptedText= "";
		String[] splitedText = encryptedText.split(" ");
		for (String element : splitedText) {
			try {
				int number = Integer.parseInt(element);
				if(number>26 || number <1) {
					return "Error ,you have entered invalid numbers";
				}
				else {
					char decryptedChar = (char)(number + (int)'a' -1); 
					decryptedText += decryptedChar;
				}
				
			} catch (Exception e) {
				return "Error ,Please enter the correct numbers!";
			}
			
		}
		return decryptedText ;

	}	
	
	
	
	
	public static String decrypt(String encryptedText, String separator) {
		String decryptedText= "";
		
		String[] splitedText = encryptedText.split(separator);
		if(splitedText.length !=0 ) {
			for (String element : splitedText) {
				try {
					int number = Integer.parseInt(element);
					if(number>26 || number <1) {
						return "Error ,you have entered invalid numbers";
					}
					else {
						char decryptedChar = (char)(number + (int)'a' -1); 
						decryptedText += decryptedChar;
					}
					
				} catch (Exception e) {
					return "Error ,Please enter the correct numbers!";
				}
			}
		}
		else {
			return "Please , Give a correct separator";
		}
		
		return decryptedText ;

	}	
}
