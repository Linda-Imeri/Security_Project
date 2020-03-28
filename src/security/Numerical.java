package security;



public class Numerical {
	public static String encode( String plaintext) {
		
		String encodedtext = "";
		
		char [] ch=new char[plaintext.length()];
		
		
		for (int i = 0; i < plaintext.length(); ++i) {
			
			ch[i] = plaintext.charAt(i); 
			char character=ch[i];
			if(Character.isDigit(character))
			{
				encodedtext="Error , you have typed a number";
				break;
				
				
			}
			
		    else if(Character.isLetter(character)) {
		    	
		    	int n = (int)character - (int)'a' + 1;
		    	encodedtext += String.valueOf(n)+" ";
		    }
			
		    else if(character==' ') {
		    	encodedtext += "    ";
		    }
			
		    else{
		    	encodedtext =" Error, you have entered invalid value";
		    	break;
		    };
	
		
		}
		
		return  encodedtext;
		
	}
	
	
	
	
	
	public static String decode(String encodedText) {
		String decodedText= "";
		String[] splitedText = encodedText.split(" ");
		for (String element : splitedText) {
			try {
				int number = Integer.parseInt(element);
				if(number>26 || number <1) {
					return "Error ,you have entered invalid numbers";
				}
				else {
					char decodedChar = (char)(number + (int)'a' -1); 
					 decodedText += decodedChar ;
				}
				
			} catch (Exception e) {
				return "Error ,Please enter the correct numbers!";
			}
			
		}
		return  decodedText ;

	}	
	
	
	
	
	public static String decode(String encodedText, String separator) {
		String  decodedText= "";
		
		String[] splitedText = encodedText.split(separator);
		if(splitedText.length !=0 ) {
			for (String element : splitedText) {
				try {
					int number = Integer.parseInt(element);
					if(number>26 || number <1) {
						return "Error ,you have entered invalid numbers";
					}
					else {
						char decodedChar = (char)(number + (int)'a' -1); 
						 decodedText += decodedChar;
					}
					
				} catch (Exception e) {
					return "Error ,Please enter numbers and make sure you have a correct separator!";
				}
			}
		}
		else {
			return "Please give encoded Text";
		}
		
		return  decodedText ;

	}	
}
