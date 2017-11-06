package cryptography_proj;
import java.net.*;
import java.io.*;
import cryptography_proj.ChatUtils;
import java.security.*;

public class ChatClient { 
	private Socket 				socket	 = null;
	private DataInputStream 	streamIn = null;
	private BufferedReader	 	console  = null;
	private DataOutputStream	streamOut= null;
	private Console				c		 = System.console();
	private ChatUtils 			util     = new ChatUtils();
	private Integrity integrity;
	private IntegrityMAC integrityMAC;

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
		if(I && A) {
			try {
				integrityMAC = new IntegrityMAC();
				Key key = integrityMAC.getKey();
				// **** TODO: Need to send key to server somehow???
				// ****       The server requires this key in order to initialize this on their end
			} catch (RuntimeException e) {
				// TODO: Do you want message to user??
			}
		}

		//Initialize Integrity only
		if (I && !A) {
			try {
				integrity = new Integrity();
			} catch (RuntimeException e) {
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
				String encrypted = util.encryptPublicRSAALT("cryptography_proj/Client/serverpublic.key", new String(aesKey.getEncoded(), "Latin1"));
				streamOut.writeUTF(encrypted);
				streamOut.flush();
				encrypted = util.encryptPublicRSAALT("cryptography_proj/Client/serverpublic.key", new String(iv, "Latin1"));
				streamOut.writeUTF(encrypted);
				streamOut.flush();
				line = streamIn.readUTF();
				System.out.println(line);
				if (line.contains("closing"))
					return;
			} catch ( Exception ioe){
				System.out.println(ioe.getMessage());
			}
		}
		
		//Chat loop
		while (!line.equals(".bye")) {
			try {  
				//Data to send
				if (console.ready()) { 
					line = console.readLine();
					if (C && I) {
						if (A) { //apply CIA (A with MACs)
             				byte[] mac = integrityMAC.signMessage(line);
              				try {
								line = util.encryptAES(iv, aesKey, line);
						  	} catch (Exception ioe) {
								System.out.println(ioe.getMessage());
								line = ".bye";
              				}
							//TODO: send message ALONG WITH byte[] mac (need to figure how we want to send byte[])

						} else { //apply CI
							byte[] digest = integrity.signMessage(line);
              				try {
								line = util.encryptAES(iv, aesKey, line);
						  	} catch (Exception ioe) {
								System.out.println(ioe.getMessage());
								line = ".bye";
             				}
							//TODO: send message ALONG WITH byte[] digest (need to figure how we want to send byte[])
						}
					} else if (C) {
						//apply C only
						try {
							line = util.encryptAES(iv, aesKey, line);
						} catch (Exception ioe) {
							System.out.println(ioe.getMessage());
							line = ".bye";
						}
					} else if (I) { //apply I only
						if (A) { //apply I with MAC
							try {
								byte[] mac = integrityMAC.signMessage(line);
								//TODO: send message ALONG WITH byte[] mac (need to figure how we want to send byte[])
							} catch (RuntimeException e) {
								System.out.println(e.getMessage());
								line = ".bye";
							}
						} else { //apply I with digest
							byte[] digest = integrity.signMessage(line);
							//TODO: send message ALONG WITH byte[] digest (need to figure how we want to send byte[])

						}
					}		
					streamOut.writeUTF(line);
					streamOut.flush();
				}
				//Data to receive
				if (streamIn.available() > 0) {
					line = streamIn.readUTF();
					if (C && I) {
						if (A) { //decrypt for CIA
             				try {
								line = util.decryptAES(iv, aesKey, line); // Decrypt
							} catch (Exception ioe) {
								System.out.println(ioe.getMessage());
							  	line = ".bye";
					  		}

							//TODO: parse input to get message and dataTag
							String message = "TODO"; // TODO: will be initialized to the message component
							byte[] dataTag = {0}; // TODO: will be initiliazed to the dataTag component
							try {
								 integrityMAC.checkIntegrity(message, dataTag);
							} catch (InvalidIntegrityException e) {
								//TODO: Integrity and/or authentication was invalid! How do we want
								//      to handle this? Alert the user? Close the connection?
							}
						} else { //decrypt for CI
            				try {
								line = util.decryptAES(iv, aesKey, line); // Decrypt
						  	} catch (Exception ioe) {
								System.out.println(ioe.getMessage());
								line = ".bye";
							}
							String message = "TODO"; // TODO: will be initialized to the message component
							byte[] digest = {0}; // TODO: will be intialized to the hash component
							try {
								 integrity.checkIntegrity(message, digest);
							} catch (InvalidIntegrityException e) {
								//TODO: Integrity was invalid! How do we want to handle this? Alert the user?
								//      Close the connection?
							}
						}

					} else if (C) {
						//decrypt for C
            			try {
							line = util.decryptAES(iv, aesKey, line);
						} catch (Exception ioe) {
							System.out.println(ioe.getMessage());
							line = ".bye";
						}

					} else if (I) { //decrypt for I
						if (A) { //decrypt for IA
							//TODO: parse input to get message and dataTag
							String message = "TODO"; // TODO: will be initialized to the message component
							byte[] dataTag = {0}; // TODO: will be initiliazed to the dataTag component
							try {
								 integrityMAC.checkIntegrity(message, dataTag);
							} catch (InvalidIntegrityException e) {
								//TODO: Integrity and/or authentication was invalid! How do we want
								//      to handle this? Alert the user? Close the connection?
							}
						} else { //decrypt for I
							String message = "TODO"; // TODO: will be initialized to the message component
							byte[] digest = {0}; // TODO: will be intialized to the hash component
							try {
								integrity.checkIntegrity(message, digest);
							} catch (InvalidIntegrityException e) {
								//TODO: Integrity was invalid! How do we want to handle this? Alert the user?
								//      Close the connection?
							}
						}
					}	
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
		if (args.length == 3)
			client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
		else if (args.length == 2)
			client = new ChatClient(args[0], Integer.parseInt(args[1]), "null");
		else
			System.out.println("Incorrect command line entry: java ChatClient <connection> <port> (<security>)");
	}
}