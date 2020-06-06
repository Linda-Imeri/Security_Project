import security.*;

public class ds {

	public static void main(String[] args) {

		String output = "The function is not valid (type 'help' to get info about the programm)";

		if (args.length >= 1) {
			switch (args[0].toString()) {

			case "help": {
				Help();
				break;
			}



			case "create-user":{
				try {
					Keys.createKeyPair(args[1]);
					output="";
				}

				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}

				break;
			}

			case "delete-user":{
				try {
					Keys.deleteUser(args[1]);
					output="";
				}

				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}

				break;
			}

			case "export-key":{
				try {
					boolean isPublic=false;
					String path="";
					if(args[1].toLowerCase().equals("public")) {
						isPublic=true;
					}
					if(args.length>=4)
						path=args[3];

					Keys.moveKeyToPath(args[2],isPublic,path);
					output="";
				}

				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}
				break;
			}

			case "import-key":{
				try {

					Keys.moveKeyFromPath(args[1],args[2]);
					output="";
				}

				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}
				break;
			}
			
			case "login":{
				try {
					Keys.login(args[1]);
					output="";
				}

				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}
				break;
			}
			case "status":{
				try {
					
					output="";
				}

				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}
				break;
			}
			case "write-message":{
				try {
					if(args.length==4) {
						Keys.encrypt(args[1],args[2],args[3]);
						output="";
					}
					else {
						Keys.encrypt(args[1],args[2]);
						output="";  }
				}
				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}
				break;
			}

			case "read-message":{
				try {
					Keys.decrypt(args[1]);
					output="";
				}
				catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}
				break;
			}

			// Faza e pare 
			//CAESAR Command
			case "caesar": {
				try {

					if (args[1].toString().equalsIgnoreCase("encrypt")) {
						try {  output = Ceasar.encrypt(Integer.valueOf(args[2]),args[3]); }
						catch (Exception e) {
							System.out.println("Error,try again and make sure that you have enter the correct shift");
							output=" ";
						}
					} 
					else if (args[1].toString().equalsIgnoreCase("decrypt")) {
						output = Ceasar.decrypt(Integer.valueOf(args[2]), args[3]);

					} 
					else if(args[1].toString().equalsIgnoreCase("brute-force")) {
						System.out.println("25 ciphertext decryption combinations.\n");
						for(int i=1;i<26;i++) {
							System.out.println(i+"->"+Ceasar.decrypt(i, args[2])+"\t");
							output="";
						}


					}

					System.out.println(output);
				} catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}

				break;
			}
			//PERMUTATION Command
			case "permutation": {
				try {
					if (args[1].toString().equalsIgnoreCase("encrypt")) {
						output = Permutation.encrypt(args[2], args[3]);
					}

					else if (args[1].toString().equalsIgnoreCase("decrypt")) {
						output = Permutation.decrypt(args[2], args[3]);
					}
					System.out.println(output);

				} catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}

				break;
			}
			//NUMERICAL Command
			case "numerical": {
				try {
					switch ((args[1].toString())) {

					case "encode": {
						output = Numerical.encode(args[2]);
						break;
					}

					case "decode": {
						if (args.length >= 5) {
							if (args[3].toString().equals("separator")) {
								output = Numerical.decode(args[2], args[4]);
							}

						}

						else {
							output = Numerical.decode(args[2]);
						}

						break;
					}

					}
					System.out.println(output);
				} catch (IndexOutOfBoundsException e) {
					System.out.println("Arguments are missing,try again ");
				}

				break;
			}

			default:
				Help();
			}
		}

		else {
			System.out.println("Welcome to our program, we will help you to use this program ");
			Help();
		}
	}



	// Help 

	public static void Help() {
		System.out.println("------ INFO ------");
		System.out.println("Komandat qe ofron ky program jane : ");
		System.out.println("1-Caesar Command\n 2-Permutation Command\n 3-Numerical Command\n");
		System.out.println("4-create-user\n 5-delete-user\n 6-import-key\n 7-export-key\n");
		System.out.println("8-write-message\n 9-read-message\n" );

	}
}