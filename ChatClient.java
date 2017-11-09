package cryptography_proj;
import java.net.*;
import java.io.*;
import cryptography_proj.ChatUtils;
import java.security.*;
import java.util.Base64;

public class ChatClient { 
	private Socket 				socket	 = null;
	private DataInputStream 	streamIn = null;
	private BufferedReader	 	console  = null;
	private DataOutputStream	streamOut= null;
	private Console				c		 = System.console();
	private ChatUtils 			util     = new ChatUtils();
	private Integrity			integrity;
	private IntegrityMAC		integrityMAC;

	public ChatClient(String serverName, int serverPort, String cia) {
		System.out.println("Establishing connection. Please wait ...");
		//Try: connect to server
		try {
			socket = new Socket(serverName, serverPort);
			System.out.println("Found: " + socket);
			start();
		} catch(UnknownHostException uhe) {
			System.out.println("Host unknown: " + uhe.getMessage());
		} catch(IOException ioe) {  
			System.out.println("Unexpected exception: " + ioe.getMessage());
		}
		
		String line = "";
		//Try: send CIA selection to server, receive success/failure
		try {
			streamOut.writeUTF(cia);
			streamOut.flush();
			line = streamIn.readUTF();
			System.out.println(line);
			if (line.contains("closing"))
				return;
		} catch(IOException ioe) {
			System.out.println(ioe.getMessage());
		}
		
		//Generate security choices array
		boolean[] sec = selector(cia);
		//
		final boolean C = sec[0];
		final boolean I = sec[1];
		final boolean A = sec[2];
		
		//Initialize Authentication
		if (A) {
			System.out.println("Enter the password:");
			try {
				while ( !console.ready());
				char[] pw = c.readPassword();

				String hash = util.hashpass(new String(pw));
				//encypt hash and send
				String encrypted = util.encryptPublicRSA("cryptography_proj/Client/serverpublic.key", hash);
				streamOut.writeUTF(encrypted);
				streamOut.flush();
				line = streamIn.readUTF();
				System.out.println(line);
				if (line.contains("closing"))
					return;

			} catch (Exception ioe) {
				System.out.println(ioe.getMessage());
			}
		}

		//Initialize Integrity and *extra* Authentication with MACs
		/*
		Key aesKey_MAC = null;
		byte[] iv_MAC = null;
		if (I && A) {
			try{
				integrityMAC = new IntegrityMAC();
				aesKey_MAC = integrityMAC.getKey();
				iv_MAC = util.generateIV();
				String keyString = integrityMAC.getKeyString();
				String encrypted = util.encryptPublicRSA("cryptography_proj/Client/serverpublic.key", keyString);
				streamOut.writeUTF(encrypted);
				streamOut.flush();
				encrypted = util.encryptPublicRSA("cryptography_proj/Client/serverpublic.key", new String(iv_MAC, "Latin1"));
				streamOut.writeUTF(encrypted);
				streamOut.flush();
				line = streamIn.readUTF();
				if (line.contains("closing"))
					return;
				line = util.decryptPrivateRSA("cryptography_proj/Client/clientprivate.key", line);
				if (!line.contains("Initialized"))
					return;
				System.out.println(line);
			} catch ( Exception ioe){
				System.out.println(ioe.getMessage());
				System.out.println("Issue when initializing integrity and MAC");
			}
		}


		//Initialize Integrity only
		if (I && !A) {
			try {
				integrity = new Integrity();
			} catch (RuntimeException e) {
				System.out.println(e.getMessage());
				line = ".bye";
				// TODO: Do you want message to user??
			}
		} */

		//Initialize Integrity only
		if (I) {
			try {
				integrity = new Integrity();
			} catch (RuntimeException e) {
				System.out.println(e.getMessage());
				line = ".bye";
				// TODO: Do you want message to user??
			}
		} 

		//Initialize Confidentiality
		Key aesKey = null;
		byte[] iv = null;
		if (C) {
			try{
				// make confidentiality work at least
				aesKey = util.makeAESKey();
				iv = util.generateIV();
				String encrypted = util.encryptPublicRSA("cryptography_proj/Client/serverpublic.key", new String(aesKey.getEncoded(), "Latin1"));
				streamOut.writeUTF(encrypted);
				streamOut.flush();
				encrypted = util.encryptPublicRSA("cryptography_proj/Client/serverpublic.key", new String(iv, "Latin1"));
				streamOut.writeUTF(encrypted);
				streamOut.flush();
				line = streamIn.readUTF();
				if (line.contains("closing"))
					return;
				line = util.decryptAES(iv, aesKey, line);
				if (!line.contains("Initialized"))
					return;
				System.out.println(line);
			} catch ( Exception ioe){
				System.out.println(ioe.getMessage());
			}
		}
		
		boolean len = true; //Message length boolean: true if length okay
		boolean bye = false;
		//Chat loop
		while (!line.equals(".bye") && !bye) {
			try {  
				//Data to send
				if (console.ready()) {
					String hash = "";
					System.out.print("Client: ");
					line = console.readLine();
					bye = line.equals(".bye");

					if (line.length() > 100) {
						System.out.println("Message cannot exceed 100 characters");
						len = false;
					} else {
						len = true;
					}
					if (C && I && len) {
						/*if (A) { //apply CIA
							hash = integrityMAC.signMessage(line);
							try {
								//TODO: make has use its own symmetric key
								line = util.encryptAES(iv, aesKey, line);
								hash = util.encryptAES(iv_MAC, aesKey_MAC, hash);
						  		} catch (Exception ioe) {
							  System.out.println(ioe.getMessage());
							  line = ".bye";
            				  }
						} else { *///apply CI
							hash = integrity.signMessage(line);
							try {
								//TODO: make has use its own symmetric key
								line = util.encryptAES(iv, aesKey, line);
								hash = util.encryptAES(iv, aesKey, hash);
							} catch (Exception ioe) {
								System.out.println("ISSUE WHEN CREATING HASH");
								System.out.println(ioe.getMessage());
								line = ".bye";
							//}
						}
					} else if (C && len) {
						//apply C only
						try {
							line = util.encryptAES(iv, aesKey, line);
						} catch (Exception ioe) {
							System.out.println(ioe.getMessage());
							line = ".bye";
						}
					} else if (I && len) { //apply I only
						/*if (A) { //apply I with MAC
							try {
								hash = integrityMAC.signMessage(line);
							} catch (RuntimeException e) {
								System.out.println(e.getMessage());
								line = ".bye";
							}
						} else {*/ //apply I with digest
							hash = integrity.signMessage(line);
						//}
					}		
					
					if (I) {
						streamOut.writeUTF(new String(hash));
						streamOut.flush();
					}
 					if (len) {
						streamOut.writeUTF(line);
						streamOut.flush();
					}
					
				}


				//Data to receive
				if (streamIn.available() > 0) {
					String hash = "";
					
					if (I) {
						hash = streamIn.readUTF();	// Read in hash/MAC first
						if (hash.equals(".bye")){
							System.out.println(hash);
							break;
						}
					}
					line = streamIn.readUTF();			// Then read in string
					if (line.equals(".bye")){
						System.out.println(line);
						break;
					}

					if (C && I) {
						/*if (A) { // Decrypt for CIA
							// TODO: *** Make hash use its OWN symmetric key ***
              				try { // Decrypt message
								line = util.decryptAES(iv, aesKey, line); // Decrypt message
								hash = util.decryptAES(iv_MAC, aesKey_MAC, hash); // Decrypt MAC
								integrityMAC.checkIntegrity(line, hash); // Check integrity of message with MAC
						  	} catch (Exception ioe) {
							 	System.out.println(ioe.getMessage());
							 	line = ".bye";
							}
						} else { */// Decrypt for CI
							// TODO: *** Make hash use its OWN symmetric key ***
              				try {
								line = util.decryptAES(iv, aesKey, line); // Decrypt message
								hash = util.decryptAES(iv, aesKey, hash); // Decrypt hash
								integrity.checkIntegrity(line, hash);
						  	} catch (Exception ioe) { // Message integrity was invalid OR issue with decrypting
								System.out.println(ioe.getMessage());
								line = ".bye";
							}
						//}

					} else if (C) {
						//decrypt for C
						try {
							line = util.decryptAES(iv, aesKey, line);
						} catch (Exception ioe) {
							System.out.println(ioe.getMessage());
							line = ".bye";
						}

					} else if (I) {
						/*if (A) { // Decrypt for IA
							// TODO: *** Make hash use its OWN symmetric key ***
              				try { 
								integrityMAC.checkIntegrity(line, hash); // Check integrity of message with MAC
						  	} catch (Exception ioe) { // Message integrity was invalid or Authenticity invalid
							 	System.out.println(ioe.getMessage());
							 	line = ".bye";
							}
						} else {*/ // Check I
							// TODO: *** Make hash use its OWN symmetric key ***
              				try {
								integrity.checkIntegrity(line, hash);
						  	} catch (Exception ioe) { // Message integrity was invalid
								System.out.println(ioe.getMessage());
								line = ".bye";
							}
						//}
					}
					System.out.print("Server: ");
					System.out.println(line);
				}
			} catch(IOException ioe) {
				System.out.println("Sending error: " + ioe.getMessage());
				break;
			}
		}
		System.out.println("Disconnected from server.");
	}
	
	//Open socket parts
	public void start() throws IOException {
		streamIn	= new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		console		= new BufferedReader(new InputStreamReader(System.in));
		streamOut	= new DataOutputStream(socket.getOutputStream());
	}
	
	//Create the security choices array
	public boolean[] selector(String sel) {
		boolean[] choice = new boolean[3];
		if (sel.contains("C") || sel.contains("c"))
			choice[0] = true;
		else
			choice[0] = false;
		
		if (sel.contains("I") || sel.contains("i"))
			choice[1] = true;
		else
			choice[1] = false;
		
		if (sel.contains("A") || sel.contains("a"))
			choice[2] = true;
		else
			choice[2] = false;
		
		return choice;
	}
	
	//Close socket parts
	public void stop() {
		try {
			if (console   != null)  console.close();
			if (streamOut != null)  streamOut.close();
			if (socket    != null)  socket.close();
		} catch(IOException ioe) {
			System.out.println("Error closing ...");
		}
	}
	
	public static void main(String args[]) {
		ChatClient client = null;
		try {
			if (args.length == 3)
				client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
			else if (args.length == 2)
				client = new ChatClient(args[0], Integer.parseInt(args[1]), "null");
			else
				System.out.println("Incorrect command line entry: java ChatClient <connection> <port> (<security>)");
		} catch (Exception e) {
			System.out.println(e.getMessage());
			System.out.println("Incorrect command line entry: java ChatClient <connection> <port> (<security>)");

		}
	}
}