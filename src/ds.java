import security.*;
public class ds {

	public static void main(String[] args) {

		String output = "The function is not valid (type 'help' to get info about the programm)";
      
		if (args.length >= 1) {
			switch (args[0].toString()) {
			
		//HELP 
			case "help": {
				Help();
				if (args.length >= 2) {
					String CommandHelp= args[1].toString().toLowerCase();
					if (CommandHelp.equals("ceasar") || CommandHelp.equals("permutation") || CommandHelp.equals("numerical"))
						Help(CommandHelp);
				}
				break;
			}
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

	
	
	// Help functions

	public static void Help() {
		System.out.println("------ INFO ------");
		System.out.println("Here you can use THREE COMMANDS : ");
		System.out.println("1- Caesar Command \n 2- Permutation Command \n 3- Numerical Command \n \n");
		System.out.println(" Steps to use the program: \n 1. Choose one Command \n 2. Encrypt / Decrypt \n"+
							"3. Type the data(depends on the command)(text,numbers, key, or whatever the command needs to work correctly)");
								
	}

	
	//Command Help 
	public static void Help(String CommandHelp) {
		String help = "Write the command name";
		if (CommandHelp.equals("ceasar")) {
			help = CommandHelp+ " -  Moves each letter of the plaintext for some positions in the alphabet.";
		}
		else if (CommandHelp.equals("permutation")) {

			help =CommandHelp+"-Transforms plaintext to block level by moving characters according to a permutation.  ";
					
		} else if (CommandHelp.equals("numerical")) {
			help = CommandHelp+ " - Each letter is replaced with its alphabetical position (letter 'a' is encoded with 1) ";
					
		}
		System.out.println(help);
	}
}