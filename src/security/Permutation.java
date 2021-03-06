package security;


public class Permutation {

	public static String encrypt(String key, String plaintext) {
		String newPlainText = plaintext;
		String visualPlainText = "";
		String visualKey = "";
		int[] positions;
		try {
			positions = extractKey(key);
		} catch (Exception e) {
			return e.getMessage();
		}

		String encryptedText = " ";


		int keyLengthMove = 0;

		//Add x to match key length
		while (newPlainText.length()%key.length()!=0) {
			newPlainText += "x";
		}		
		int repeatKey = newPlainText.length()/key.length();
		
		//Encrypt
		for(int i=0; i < newPlainText.length(); i++) {
			int keyPosition=i%key.length();
			if (keyPosition==0 && i>0) {
				keyLengthMove+=key.length();
				encryptedText += " ";
				visualPlainText+= " ";
			}
			int currentPosition = positions[keyPosition];
			encryptedText+=newPlainText.charAt(currentPosition+keyLengthMove-1);
			visualPlainText += newPlainText.charAt(i);
		}		
		
		for (int i = 0; i < repeatKey; i++) {
			if(i != repeatKey-1) {
			visualKey+= key +" ";}
			else {
				visualKey+=key;
			}
		}	
		
		System.out.println("Plaintext \t "+visualPlainText);
		System.out.println("Key \t\t "+visualKey);
		System.out.println("Encrypted \t"+encryptedText);
		return "";
	}





	public static String decrypt(String key, String encryptedText) {
		String decryptedText="";
		int[] positions;
		try {
			positions = extractKey(key);
		} catch (Exception e) {
			return e.getMessage();
		}	
		char[] temp = new char[key.length()];

		for(int i=0; i <encryptedText.length(); i++)
		{
			int keyPosition=i%key.length();			
			char letter=encryptedText.charAt(i);
			temp[positions[keyPosition]-1] = letter;		
			if (keyPosition==key.length()-1 && i>0) {
				decryptedText += String.valueOf(temp);	
				temp = new char[key.length()];
			}
		}

		if(decryptedText.lastIndexOf('x')==decryptedText.length()-1) {
			decryptedText = decryptedText.substring(0, decryptedText.length()-1);
		}

		return decryptedText;
	}


	private static int[] extractKey(String key) throws Exception {
		int[] positions = new int[key.length()];
		//Get key positions		
		for(int i=0; i < key.length(); i++) {
			try {
				positions[i] = Integer.parseInt(String.valueOf(key.charAt(i)));
			} catch (Exception e) {
				throw new Exception("Mistake on key");
			}			
		}


		return positions;
	}

}

