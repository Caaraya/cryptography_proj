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
	private Integrity			integrity= null;

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


		//Initialize Integrity
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

					if (I && len) {
						//apply I
						hash = integrity.signMessage(line);
					}
					if (C && len) {
						//apply C
						try {
							line = util.encryptAES(iv, aesKey, line);
						} catch (Exception ioe) {
							System.out.println(ioe.getMessage());
							line = ".bye";	
						}
					}	

					if (I) {
						try { // send hash
							hash = util.encryptPrivateRSA("cryptography_proj/Client/clientprivate.key", hash);
							int mid = hash.length()/2;
							String hash1 = util.encryptPublicRSA("cryptography_proj/Client/serverpublic.key", hash.substring(0, mid));
							String hash2 = util.encryptPublicRSA("cryptography_proj/Client/serverpublic.key", hash.substring(mid));
							streamOut.writeUTF(hash1);
							streamOut.flush();
							streamOut.writeUTF(hash2);
							streamOut.flush();
						} catch (Exception ioe) {
							System.out.println(ioe.getMessage());
							line = ".bye";
						}
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
						String hash1 = streamIn.readUTF();	// Read in hash1
						String hash2 = streamIn.readUTF();  // Read in hash2
						try {
							hash1 = util.decryptPrivateRSA("cryptography_proj/Client/clientprivate.key", hash1);
							hash2 = util.decryptPrivateRSA("cryptography_proj/Client/clientprivate.key", hash2);
							hash = hash1 + hash2;
							hash = util.decryptPublicRSA("cryptography_proj/Client/serverpublic.key", hash);
						} catch (Exception ioe) {
							System.out.println(ioe.getMessage());
							line = ".bye";
						}
							if (hash.equals(".bye")){
							System.out.println(hash);
							break;
						}
					}
					line = streamIn.readUTF();		// Then read in string
					if (line.equals(".bye")){
						System.out.println(line);
						break;
					}

					if (C) {
						//decrypt for C
						try {
							line = util.decryptAES(iv, aesKey, line); // Decrypt message
						} catch (Exception ioe) { // issue with decrypting
							System.out.println(ioe.getMessage());
							line = ".bye";
						}
					}

					if (I) {
						//check integrity
						try {
							integrity.checkIntegrity(line, hash);
						} catch (Exception ioe) { // Message integrity was invalid
							System.out.println(ioe.getMessage());
							line = ".bye";
						}
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
			if (args.length == 3) {
				client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
			} else if (args.length == 2) {
				client = new ChatClient(args[0], Integer.parseInt(args[1]), "null");
			} else {
				System.out.println("Incorrect command line entry: java cryptography_proj.ChatClient <connection> <port> <security>");
				System.out.println("or: java cryptography_proj.ChatClient <connection> <port>");
			}
		} catch (Exception e) {
			if (e instanceof NullPointerException )
				System.out.println("Invalid port: could not connect");
			else if (e instanceof NumberFormatException)
				System.out.println("Invalid port: value must be a number");
			else 
				System.out.println(e.getMessage());
			System.out.println("Incorrect command line entry: java cryptography_proj.ChatClient <connection> <port> <security>");
			System.out.println("or: java cryptography_proj.ChatClient <connection> <port>");
		}
	}
}