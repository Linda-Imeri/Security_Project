package security;

import java.awt.RenderingHints.Key;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;



public class Keys {
	public static final int KEY_SIZE = 2048;
	public static final String KEY_PATH = "keys/";

	
	
	public static void encrypt(String name, String message ) {
		byte[] iv = generateRandom();
		SecretKey desKey = generateDESKey();
		
		Base64.Encoder encoder = Base64.getEncoder();
		try {
			String encodedName = encoder.encodeToString(name.getBytes("UTF-8"));
			String encodedIV = encoder.encodeToString(iv);
			
			//Encrypt desKey		
			byte[] desKeyBytes = desKey.getEncoded();
			
			PublicKey publicKey = importPublicKey(name);
			if(publicKey!=null) {
				byte[] encryptedDesKey = encryptKey(desKeyBytes, publicKey);
				String encodedDesKey = encoder.encodeToString(encryptedDesKey);
				
				byte[] encryptedMessage = encryptMessage(message, desKey);
				String encodedMessage = encoder.encodeToString(encryptedMessage);
				
				String ciphertext = encodedName +"."+encodedIV+"."+encodedDesKey+"."+encodedMessage;
				System.out.println(ciphertext);
			}		
			
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		
	}
	
public static void decrypt(String cipher) {
		
		Base64.Decoder decoder = Base64.getDecoder();
		try {
			String ciphertext = cipher;
			if (cipher.contains(".txt")) {
				ciphertext = new String(Files.readAllBytes(Paths.get(ciphertext)));
			}
			String[] components = ciphertext.split("\\.");
			byte[] decodedNameBytes = decoder.decode(components[0]);
			String decodedName = new String(decodedNameBytes, "UTF-8");
			System.out.println("Marresi: "+decodedName);
			
			//Decrypt desKey		
			byte[] desKeyEncryptedBytes = decoder.decode(components[2]);
			PrivateKey privateKey = importPrivateKey(decodedName);
			if (privateKey != null) {
				byte[] desKeyDecryptedBytes = decryptKey(desKeyEncryptedBytes, privateKey);
				SecretKey desKey = new SecretKeySpec(desKeyDecryptedBytes, 0, desKeyDecryptedBytes.length, "DES");
				
				byte[] decodedMessage = decoder.decode(components[3]);
				String decryptedMessage = decryptMessage(decodedMessage, desKey);
				System.out.println("Mesazhi: "+decryptedMessage);
			}

		} catch (UnsupportedEncodingException e) {
			System.out.println("Gabim gjate dekriptimit");
		} catch (IOException e) {
			System.out.println("Gabim ne lexim te fajllit");
		}
	}
public static void encrypt(String name, String message, String filename) {
	byte[] iv = generateRandom();
	SecretKey desKey = generateDESKey();
	
	Base64.Encoder encoder = Base64.getEncoder();
	try {
		String encodedName = encoder.encodeToString(name.getBytes("UTF-8"));
		String encodedIV = encoder.encodeToString(iv);
		
		//Encrypt desKey		
		byte[] desKeyBytes = desKey.getEncoded();
		
		PublicKey publicKey = importPublicKey(name);
		if(publicKey!=null) {
			byte[] encryptedDesKey = encryptKey(desKeyBytes, publicKey);
			String encodedDesKey = encoder.encodeToString(encryptedDesKey);
			
			byte[] encryptedMessage = encryptMessage(message, desKey);
			String encodedMessage = encoder.encodeToString(encryptedMessage);
			
			String ciphertext = encodedName +"."+encodedIV+"."+encodedDesKey+"."+encodedMessage;
			
			Writer out = new FileWriter(filename);
			System.out.println("Mesazhi i enkriptuar u ruajt ne fajllin '"+filename);
			out.write(ciphertext);
			out.close();
		}
	} catch (IOException e) {
		e.printStackTrace();
	}
	
}

	public static byte[] encryptMessage(String text, SecretKey sk) {
		try {
			if (sk != null) {
				Cipher cipher = Cipher.getInstance("DES");
				cipher.init(Cipher.ENCRYPT_MODE, sk);
				byte[] input = text.getBytes();	  
				byte[] cipherTextBytes = cipher.doFinal(input);	
				
				return cipherTextBytes;
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String decryptMessage(byte[] cypher, SecretKey sk) {
		try {
			if (sk != null) {
				Cipher cipher = Cipher.getInstance("DES");
				cipher.init(Cipher.DECRYPT_MODE, sk);
				byte[] plainTextBytes = cipher.doFinal(cypher);
				String plainText = new String(plainTextBytes);
				return plainText;
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static SecretKey generateDESKey() {
		try {
			KeyGenerator generator = KeyGenerator.getInstance("DES");
			SecretKey desKey = generator.generateKey();
			return desKey;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static byte[] encryptKey(byte[] input, PublicKey key) {
		Cipher cipher;
		byte[] cipherTextBytes= null;
		try {
			if (key != null) {
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, key);
				cipher.update(input);
				cipherTextBytes = cipher.doFinal();	 
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException  e) {
			e.printStackTrace();
		}
		return cipherTextBytes;
	}
	
	private static byte[] decryptKey(byte[] encyptedBytes, PrivateKey key) {
		Cipher cipher;
		byte[] plainTextBytes = null;
		try {
			if (key !=null) {
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.DECRYPT_MODE, key);
				plainTextBytes = cipher.doFinal(encyptedBytes);
			} 
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException  e) {
			e.printStackTrace();
		}
		return plainTextBytes;
	}
	
	public static void createKeyPair(String name) {
		
		KeyPairGenerator kpg;
		try {
			 int gjatesia=name.length();
				char [] ch=new char[gjatesia];
			
				for (int i = 0; i < gjatesia; i++) {
					
					ch[i] = name.charAt(i); 
					char character=ch[i];
					if(((Character.isLetter(character))==false) && (character!='_')&&(Character.isDigit(character))==false) {

				        System.out.println("Shtypni emrin ne formatin e duhur");
				        return;
					}}
				
			String privateKeyName=KEY_PATH+name+".pem";
			String publicKeyName=KEY_PATH+name+".pub.pem";
			if(Files.exists(Paths.get(privateKeyName))||Files.exists(Paths.get(publicKeyName))){
				System.out.println("Qelesi ' "+name +" ' ekziston paraprakisht");
				return;
			}
			
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(KEY_SIZE);
			KeyPair kp = kpg.generateKeyPair();
			PublicKey pub = kp.getPublic();
			PrivateKey pvt = kp.getPrivate();
						
			Base64.Encoder encoder = Base64.getEncoder();
			
			//Save private key
			Writer out = new FileWriter(privateKeyName);
			out.write("-----BEGIN RSA PRIVATE KEY-----\n");
			out.write(encoder.encodeToString(pvt.getEncoded()));
			out.write("\n-----END RSA PRIVATE KEY-----\n");
			out.close();
			
			
			System.out.println("Eshte krijuar celesi privat 'keys/"+name+"'.pem");
			//Save public key
			
			
			out = new FileWriter(publicKeyName);
			out.write("-----BEGIN RSA PUBLIC KEY-----\n");
			out.write(encoder.encodeToString(pub.getEncoded()));
			out.write("\n-----END RSA PUBLIC KEY-----\n");
			out.close();
			System.out.println("Eshte krijuar celesi publik 'keys/"+name+"'.pub.pem");
			
				}
		    catch (Exception e) {
			e.printStackTrace();
		}	
	}
	public static void deleteUser(String name) {
		Path privateKey = Paths.get(KEY_PATH+name+".pem");
		Path publicKey = Paths.get(KEY_PATH+name+".pub.pem");
		if(Files.exists(privateKey)) {
			try {
				Files.delete(privateKey);
				System.out.println("Eshte larguar celesi privat 'keys/"+name+".pem");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else {
			System.out.println("Gabim: Celesi privat '"+name+"'nuk ekziston");

		}
		if(Files.exists(publicKey)) {
			try {
				Files.delete(publicKey);
				System.out.println("Eshte larguar celesi publik 'keys/"+name+".pub.pem");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else {
			System.out.println("Gabim: Celesi publik '"+name+"'nuk ekziston");

		}
	}
	private static void importKey(String name) {
		PrivateKey privateKey = importPrivateKey(name);
		PublicKey publicKey = importPublicKey(name);
	}
		
	private static PublicKey importPublicKey(String name) {
		Base64.Decoder decoder = Base64.getDecoder();		
		String publicKeyString;
		PublicKey publicKey = null; 
		try {
			//Import public key
			publicKeyString = new String(Files.readAllBytes(Paths.get(KEY_PATH+name+".pub.pem")));
			publicKeyString = publicKeyString.split("\n")[1];			
			byte[] publicKeyBytes = decoder.decode(publicKeyString);
			X509EncodedKeySpec pubKeySpecification = new X509EncodedKeySpec(publicKeyBytes);
			KeyFactory pubKeyFactory = KeyFactory.getInstance("RSA");
			publicKey = pubKeyFactory.generatePublic(pubKeySpecification);
		} catch (IOException e) {
			System.out.println("Gabim tek leximi i qelsit");
		}
		catch (Exception e) {
		System.out.println("Gabim tek leximi i qelsit");
		}
		return publicKey;
	}
	
	private static PrivateKey importPrivateKey(String name) {
		Base64.Decoder decoder = Base64.getDecoder();		
		String privateKeyString;
		PrivateKey privateKey = null;
		try {
			//Import private key
			privateKeyString = new String(Files.readAllBytes(Paths.get(KEY_PATH+name+".pem")));
			privateKeyString = privateKeyString.split("\n")[1];			
			byte[] privateKeyBytes = decoder.decode(privateKeyString);
			PKCS8EncodedKeySpec keySpecification = new PKCS8EncodedKeySpec(privateKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(keySpecification);
		} catch (IOException e) {
			System.out.println("Gabim tek leximi i qelsit");
		}
		catch (Exception e) {
			System.out.println("Gabim tek leximi i qelsit");
		}
		return privateKey;
	}

	private static byte[] generateRandom() {
		Random rd = new Random();
	    byte[] arr = new byte[7];
	    rd.nextBytes(arr);
	    return arr;
	}
	
	public static void moveKeyToPath(String name, boolean isPublic, String path) {
		Base64.Encoder encoder = Base64.getEncoder();
		String privateKeyName=KEY_PATH+name+".pem";
		String publicKeyName=KEY_PATH+name+".pub.pem";
		if(Files.notExists(Paths.get(privateKeyName))||Files.notExists(Paths.get(publicKeyName))) {
		System.out.println("Qelesi ' "+name +" ' nuk ekziston");
			return;
		}
	
		if(isPublic) {
			if(path.isEmpty()) {
				System.out.println(encoder.encodeToString(importPublicKey(name).getEncoded()));
			}
			else {
				Path source = new File(KEY_PATH+name+".pub.pem").toPath();
				Path destination = Paths.get(path, name+".pub.pem");
				try {
					Files.copy(source, destination, StandardCopyOption.COPY_ATTRIBUTES);
					System.out.println("Qelesi publik u ruajt ne "+path);
				} catch (Exception e) {
					System.out.println("Gabim: Nuk u gjet file");
				}
			}
		}
		else {
			if(path.isEmpty()) {
				System.out.println(encoder.encodeToString(importPrivateKey(name).getEncoded()));
			}
			else {
				Path source = new File(KEY_PATH+name+".pem").toPath();
				Path destination = Paths.get(path, name+".pem");
				try {
					Files.copy(source, destination, StandardCopyOption.COPY_ATTRIBUTES);
					System.out.println("Qelesi privat u ruajt ne "+path);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	private static boolean getKeyType(String keyString) {
		boolean isPublic = true;
		if(keyString.contains("RSA PRIVATE KEY")) isPublic = false;
		return isPublic;
	}
	private static void generateFromPrivate(String text, String name) {
		Base64.Decoder decoder = Base64.getDecoder();
		Base64.Encoder encoder = Base64.getEncoder();		

		PrivateKey privateKey = null;
		try {
			//Import private key
			String privateKeyString = text.split("\n")[1];			
			byte[] privateKeyBytes = decoder.decode(privateKeyString);
			PKCS8EncodedKeySpec keySpecification = new PKCS8EncodedKeySpec(privateKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(keySpecification);
			RSAPrivateCrtKey privateKeyCrt = (RSAPrivateCrtKey)privateKey;
			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKeyCrt.getModulus(), privateKeyCrt.getPublicExponent());
			PublicKey generatedPublicKey = keyFactory.generatePublic(publicKeySpec);
			
			//Save public key
			Writer out = new FileWriter(KEY_PATH+name+".pub.pem");
			out.write("-----BEGIN RSA PUBLIC KEY-----\n");
			out.write(encoder.encodeToString(generatedPublicKey.getEncoded()));
			out.write("\n-----END RSA PUBLIC KEY-----\n");
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void moveKeyFromPath(String name, String path) {
		String privateKeyName = KEY_PATH+name+".pem";
		String publicKeyName = KEY_PATH+name+".pub.pem";
		boolean isPublic = true;		
		
		//Check if the key already exists in keys
		if(Files.exists(Paths.get(publicKeyName))||Files.exists(Paths.get(privateKeyName))) {
			System.out.println("Celesi '"+ name + "' ekziston");
			return;
		}
		
		Base64.Encoder encoder = Base64.getEncoder();
		if(path.contains("http://") || path.contains("https://")){
			try {
				StringBuilder result = new StringBuilder();
			    URL url = new URL(path);
			    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			    conn.setRequestMethod("GET");
			    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			    String line;
			    while ((line = rd.readLine()) != null) {
			       result.append(line);
			    }
			    rd.close();
			    isPublic = getKeyType(result.toString());
			    if(isPublic) {			    	
			    	Writer out = new FileWriter(publicKeyName);
					out.write("-----BEGIN RSA PUBLIC KEY-----\n");
					out.write(encoder.encodeToString(result.toString().getBytes()));
					out.write("\n-----END RSA PUBLIC KEY-----\n");
					out.close();
					System.out.println("Celesi publik u ruajt ne fajllin "+publicKeyName);
			    }
			    else {
					
			    	Writer out = new FileWriter(privateKeyName);
					out.write("-----BEGIN RSA PRIVATE KEY-----\n");
					out.write(encoder.encodeToString(result.toString().getBytes()));
					out.write("\n-----END RSA PRIVATE KEY-----\n");
					out.close();
					System.out.println("Celesi privat u ruajt ne fajllin "+privateKeyName);
					
					//Generate public key
					generateFromPrivate(result.toString(), name);
					System.out.println("Celesi publik u ruajt ne fajllin "+publicKeyName);				
			    }
			    
			}
			catch (Exception e) {
				System.out.println("Gabim gjate leximit te uebsajt-it!");
			}
			
		}
		else {
			//Check if imported key exists and get its type
			if(Files.exists(Paths.get(path))) {
				try {
					String keyString = new String(Files.readAllBytes(Paths.get(path)));
					isPublic = getKeyType(keyString);
				} catch (IOException e) {
					System.out.println("Gabim gjate leximit te fajllit!");
					return;
				}
			}
			else {
				System.out.println("Fajlli nuk u gjet!");
				return;
			}
						
			
			if(isPublic) {
				Path destination = new File(KEY_PATH+name+".pub.pem").toPath();
				Path source = Paths.get(path);
				try {
					Files.copy(source, destination, StandardCopyOption.COPY_ATTRIBUTES);
					System.out.println("Celesi publik u ruajt ne fajllin "+KEY_PATH+name+".pub.pem");
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			else {
				Path destination = new File(KEY_PATH+name+".pem").toPath();
				Path source = Paths.get(path);
				try {
					Files.copy(source, destination, StandardCopyOption.COPY_ATTRIBUTES);
					System.out.println("Celesi privat u ruajt ne fajllin "+KEY_PATH+name+".pem");
					
					//Generate public key
					String readPrivateKey = new String(Files.readAllBytes(source));
					generateFromPrivate(readPrivateKey, name);
					System.out.println("Celesi publik u ruajt ne fajllin "+publicKeyName);
				} catch (IOException e) {
					System.out.println("Gabim gjate leximit te fajllit");
				}
			}
		}
		
	}

}
