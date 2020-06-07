package security;

import java.io.Console;
import java.awt.RenderingHints.Key;
import java.io.BufferedReader;
import java.io.Console;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.spec.SecretKeySpec;
import java.util.Date;



public class Keys {

	public static final int KEY_SIZE = 2048;
	public static final String KEY_PATH = "keys/";
	private final static char[] hexArray="0123456789ABCDEF".toCharArray();
	
	
	
	private static Connection getConnection() {
		String host="jdbc:mysql://localhost:3306/siguri";
		String uName="root";
		String uPass="";
		
		try {
			Connection mycon=DriverManager.getConnection(host,uName,uPass);
			return mycon;
		}
		catch(SQLException err) {
			System.out.println(err.getMessage());
		}
		return null;
	}
	
	public static String createJWT(String issuer, long ttlMillis) {
		  
	    long nowMillis = System.currentTimeMillis();	    
	    PrivateKey privateKey = importPrivateKey(issuer);

	    String token = JWT.create()
	            .withIssuer(issuer)
	            .withExpiresAt(new Date(nowMillis + ttlMillis))
	            .sign(Algorithm.RSA256((RSAKey) privateKey));
	    return token;
	}
	
	public static boolean verifyJWT(String token, String issuer) {
		try {		    
		    PublicKey publicKey = importPublicKey(issuer);
	
		    Algorithm algorithm = Algorithm.RSA256((RSAKey) publicKey);
		    JWTVerifier verifier = JWT.require(algorithm)
		        .withIssuer(issuer)
		        .build(); //Reusable verifier instance
		    DecodedJWT jwt = verifier.verify(token);
		    return true;
		}catch (JWTVerificationException exception){
		    return false;
		}
	}
	
	public static boolean authenticate(String user, String password) {
		try {
			Connection conn = getConnection();
			Statement myStmt=conn.createStatement();
						
			String getSaltQuery = "select Salt from userat where Emri='"+user+"';";
			ResultSet saltSet = myStmt.executeQuery(getSaltQuery);
			String salt = "";
			if(saltSet.next()) salt = saltSet.getString("Salt");
			else {
				conn.close();
				return false;
			} 
			
			byte[] saltDecoded = Base64.getDecoder().decode(salt);
			String Hashedpassword=generateHash(password,saltDecoded);

			String authenticateQuery="select * from userat where Emri='"+user+"' AND Password='"+Hashedpassword+"';";
			ResultSet userSet = myStmt.executeQuery(authenticateQuery);
			if(userSet.next()) {
				String token = createJWT(user,120000);
				String updateQuery="update userat set Token = '"+token+"' where Emri='"+user+"' AND Password='"+Hashedpassword+"';";
				myStmt.executeUpdate(updateQuery);
				System.out.println("Token: " + token);
				conn.close();
				return true;
			}
			else {
				conn.close();
				return false;
			}
			
		}
		catch(SQLException err) {
			System.out.println(err.getMessage());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	
	public static void encrypt(String name, String message, String token) {
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
				
				String signature = "";
				if(token.length()>0) {
					Connection conn = getConnection();
					Statement myStmt=conn.createStatement();
								
					String getUserQuery = "select Emri from userat where Token='"+token+"';";
					ResultSet userSet = myStmt.executeQuery(getUserQuery);
					String user = "";
					if(userSet.next()) user = userSet.getString("Emri");
					conn.close();
					if(!user.equals("")) {
						if(verifyJWT(token, user)) {
							PrivateKey privateKey = importPrivateKey(user);
							String userEncoded = encoder.encodeToString(user.getBytes("UTF-8"));
							signature = "."+userEncoded+"."+signDocument(privateKey, encryptedMessage);
						}						
					}					
				}
				String ciphertext = encodedName +"."+encodedIV+"."+encodedDesKey+"."+encodedMessage+signature;
				System.out.println("Ciphertext:\n"+ciphertext);
			}		

		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			System.out.println("Gabim gjate leximit te perdoruesit nga tokeni");
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
				
				if(components.length>4) {
					byte[] decodedSenderBytes = decoder.decode(components[4]);
					String decodedSender = new String(decodedSenderBytes, "UTF-8");
					System.out.println("Derguesi: "+decodedSender);
					
					byte[] decodedSignatureBytes = decoder.decode(components[5]);
					
					PublicKey publicKey = importPublicKey(decodedSender);
					boolean validSignature = verifySignature(publicKey, decodedSignatureBytes, decodedMessage);
					System.out.println("Nenshkrimi: "+validSignature);
				}
			}

		} catch (UnsupportedEncodingException e) {
			System.out.println("Gabim gjate dekriptimit");
		} catch (IOException e) {
			System.out.println("Gabim ne lexim te fajllit");
		}
	}
	public static void encrypt(String name, String message, String filename, String token) {
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

				String signature = "";
				if(token.length()>0) {
					Connection conn = getConnection();
					Statement myStmt=conn.createStatement();
								
					String getUserQuery = "select Emri from userat where Token='"+token+"';";
					ResultSet userSet = myStmt.executeQuery(getUserQuery);
					String user = "";
					if(userSet.next()) user = userSet.getString("Emri");
					conn.close();
					if(!user.equals("")) {
						if(verifyJWT(token, user)) {
							PrivateKey privateKey = importPrivateKey(user);
							String userEncoded = encoder.encodeToString(user.getBytes("UTF-8"));
							signature = "."+userEncoded+"."+signDocument(privateKey, encryptedMessage);
						}
					}					
				}
				String ciphertext = encodedName +"."+encodedIV+"."+encodedDesKey+"."+encodedMessage+signature;

				Writer out = new FileWriter(filename);
				System.out.println("Mesazhi i enkriptuar u ruajt ne fajllin '"+filename);
				out.write(ciphertext);
				out.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			System.out.println("Gabim gjate leximit te tokenit");
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
	public static void InsertToDatabase(String name,String password) throws NoSuchAlgorithmException  {	
		try {
			Statement myStmt=getConnection().createStatement();
			
			byte[] salt=createSalt();
			String saltEncoded = Base64.getEncoder().encodeToString(salt);
			String Hashedpassword=generateHash(password,salt);
			
			String insert="insert into userat"
					+"(Emri,Salt,Password)"
					+"values('"+name+"','"+saltEncoded+"','"+Hashedpassword+"')";
			myStmt.executeUpdate(insert);
			System.out.println("Eshte krijuar shfrytezuesi '"+name+"'");
		}
		catch(SQLException err) {
			System.out.println(err.getMessage());
		}
	}
	
	public static void DeleteFromDatabase(String name) throws NoSuchAlgorithmException  {
		try {
			Statement myStmt=getConnection().createStatement();
			String sql="delete from userat where Emri='"+name+"'";
			myStmt.executeUpdate(sql);
			
			System.out.println("Eshte fshire shfrytezuesi '"+name+"'");
		}
		catch(SQLException err) {
			System.out.println(err.getMessage());
		}
	}

	public static String generateHash(String password,byte[] salt) throws NoSuchAlgorithmException {
		MessageDigest digest=MessageDigest.getInstance("MD5");
		digest.reset();
		digest.update(salt);
		byte[] hash=digest.digest(password.getBytes());
		return  Base64.getEncoder().encodeToString(hash);
	}
	private static byte[] createSalt() {
		byte[] bytes=new byte[20];
		SecureRandom random=new SecureRandom();
		random.nextBytes(bytes);
		return bytes;
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
			Console console = System.console();
			if (console == null) {
				System.out.println("Couldn't get Console instance");

			}

			char[] passwordArray = console.readPassword("Jepni fjalekalimin: ");
			if(passwordArray.length<6) {
				System.out.println("Fjalekalimi eshte i shkurter,provoni perseri");
				return;
			} 
			char[] passwordConfirmArray = console.readPassword("Perserit fjalekalimin: ");
			

			boolean ConfirmPassword=false;
			if(Arrays.equals(passwordArray, passwordConfirmArray)) {ConfirmPassword=true;}
			if(ConfirmPassword==true)
			{
				
			}
			else {
				System.out.println("Gabim : Fjalekalimet nuk perputhen");
				return;
			}
			
			InsertToDatabase(name,new String(passwordArray));
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
	public static void deleteUser(String name)  {
		Path privateKey = Paths.get(KEY_PATH+name+".pem");
		Path publicKey = Paths.get(KEY_PATH+name+".pub.pem");
		try {
			DeleteFromDatabase(name);
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
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
	public static void login(String name) {

		int gjatesia=name.length();
		char [] ch=new char[gjatesia];

		for (int i = 0; i < gjatesia; i++) {

			ch[i] = name.charAt(i); 
			char character=ch[i];
			if(((Character.isLetter(character))==false) && (character!='_')&&(Character.isDigit(character))==false) {

				System.out.println("Shtypni emrin ne formatin e duhur");
				return;
			}}
		Console console = System.console();
		if (console == null) {
			System.out.println("Couldn't get Console instance");

		}
		char[] passwordArray = console.readPassword("Jepni fjalekalimin: ");
		if(!authenticate(name, new String(passwordArray))) {
			System.out.println("Shfrytezusi ose fajlekalimi jane gabim!");
		};
		
	}

	public static void status(String token) {	
		
		try {
			Connection conn = getConnection();
			Statement myStmt = conn.createStatement();
				
			String getUserQuery = "select Emri from userat where Token='"+token+"';";
			ResultSet userSet = myStmt.executeQuery(getUserQuery);
			String user = "";
			if(userSet.next()) user = userSet.getString("Emri");
			conn.close();
			if(!user.equals("")) {
				boolean validToken = verifyJWT(token, user);
				if(validToken) {
					System.out.println("User: "+user);
					System.out.println("Valid: Po");
				}
				else {
					System.out.println("Tokeni nuk eshte valid");
				}
			}
			else {
				System.out.println("Tokeni nuk eshte valid");
			}
		}
		catch (SQLException e) {
			System.out.println("Gabim gjate leximit te tokenit");
		}
	}
	
	public static String signDocument(PrivateKey privateKey,  byte[] message) {		     
		try {
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(privateKey);
			sign.update(message);
			byte[] bytesSigned = sign.sign();
			return Base64.getEncoder().encodeToString(bytesSigned);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
			return null;
		}
	}
	public static boolean verifySignature(PublicKey publicKey, byte[] bytesSigned, byte[] message) {		     
		try {			
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initVerify(publicKey);
			sign.update(message);
			boolean validSignature = sign.verify(bytesSigned);
			return validSignature;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			System.out.println("Gabim gjate verifikimit te mesazhit");
			return false;
		}
	}
}
