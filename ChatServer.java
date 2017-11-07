package cryptography_proj;
import java.net.*;
import java.io.*;
import cryptography_proj.ChatUtils;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;

public class ChatServer {  
	private Socket				socket		= null;
	private ServerSocket		server		= null;
	private DataInputStream		streamIn	= null;
	private BufferedReader		console		= new BufferedReader(new InputStreamReader(System.in));
	private DataOutputStream	streamOut	= null;
	private Console 			c 			= System.console();
	private ChatUtils 			util        = new ChatUtils();
	private Integrity			integrity;
	private IntegrityMAC		integrityMAC;

	public ChatServer(int port, String sCia) {
		System.out.println("Beginning server");
		//Create server's security array
		boolean[] sSel = selector(sCia);
		final boolean C = sSel[0];
		final boolean I = sSel[1];
		final boolean A = sSel[2];
		
		if (A) {
			//get password for server, check
			System.out.println("Enter the password:");
			try {

				while (!console.ready());
				char[] pw = c.readPassword();

				String hash = util.hashpass(new String(pw));
				String expectedhash = util.readFileAsString("cryptography_proj/Server/server_hash.txt");

				if(!hash.equals(expectedhash)){
					System.out.println("Incorrect password, closing session");
					return;
				}
			} catch (IOException ioe) {
				System.out.println(ioe.getMessage());
			}
		}
		
		//Try: open socket
		try {
			System.out.println("Binding to port " + port + ", please wait	...");
			server = new ServerSocket(port);
			System.out.println("Server started: " + server);

			//Server runs for all time
			while(true) {
				//Wait for client connection
				System.out.println("Waiting for a client ...");
				socket = server.accept();
				System.out.println("Client found: " + socket);
				open();

				//Create security choice array for client
				String cCia = streamIn.readUTF();
				boolean[] cSel = selector(cCia);
				
				boolean done = false;
				
				//Compare security choice arrays, return success/failure to client
				if ( (sSel[0] == cSel[0]) && (sSel[1] == cSel[1]) && (sSel[2] == cSel[2]) ) {
					System.out.println("Client connected");
					try {
						streamOut.writeUTF("Successfully connected to server");
						streamOut.flush();
					} catch(IOException ioe) {
						System.out.println(ioe.getMessage());
					}
				} else {
					System.out.println("Security types did not match: closing connection.");
					try {
						streamOut.writeUTF("Incompatible security types, closing connection");
						streamOut.flush();
					} catch(IOException ioe) {
						System.out.println(ioe.getMessage());
					}
					close();
					done = true;
				}
				
				//Authentication
				if (A && !done) {
					try {
						// get encrypted hash
						String encryptedhash = streamIn.readUTF();
						String hash = util.decryptPrivateRSA("cryptography_proj/Server/serverprivate.key", encryptedhash);
						String expectedhash = util.readFileAsString("cryptography_proj/Server/client_hash.txt");
						if(!hash.equals(expectedhash)){
							// failed authentication
							System.out.println("Incorrect client password: closing connection.");
							streamOut.writeUTF("Incorrect password, closing connection");
							streamOut.flush();
							close();
							done = true;
						} else {
							// succeeded authentication
							streamOut.writeUTF("Successfully authenticated");
							streamOut.flush();
						}
					} catch(Exception ioe) {
						System.out.println(ioe.getMessage());
					}
				}
				
				//Initialize Integrity and *extra* Authentication with MACs
				Key aesKey_MAC = null;
				byte[] iv_MAC = null;
				if(I && A && !done) {
					try {
						String encryptedKeyMAC = streamIn.readUTF();
						String encryptedIVKey = streamIn.readUTF();
						String aesKey_MAC_String = util.decryptPrivateRSA("cryptography_proj/Server/serverprivate.key", encryptedKeyMAC);
						iv_MAC = util.decryptPrivateRSA("cryptography_proj/Server/serverprivate.key", encryptedIVKey).getBytes("Latin1");
						integrityMAC = new IntegrityMAC(aesKey_MAC_String);
						aesKey_MAC = integrityMAC.getKey();
						String message ="Initialized symmetric keys on server for MAC";
						String encryptedMessage = util.encryptPublicRSA("cryptography_proj/Server/clientpublic.key", message);
						streamOut.writeUTF(encryptedMessage);
						System.out.println(message);
						streamOut.flush();
					} catch (Exception ioe) {
						System.out.println(ioe.getMessage());
						streamOut.writeUTF("Error initializing closing client");
						streamOut.flush();
					}
				}

				//Initialize Integrity only
				if (I && !A && !done) {
					try {
						integrity = new Integrity();
					} catch (RuntimeException ioe) {
						// TODO: Do you want message to user??
						System.out.println(ioe.getMessage());
						System.out.println(ioe.getMessage());
						streamOut.writeUTF("Error initializing closing client");
						streamOut.flush();
					}
				} 
				
				// needed key and initialization vector
				Key aesKey = null;
				byte[] iv = null;

				//Initialize Confidentiality make it work!
				if (C && !done) {
					try {
						String message = streamIn.readUTF();
						String encryptediv= streamIn.readUTF();
						message = util.decryptPrivateRSA("cryptography_proj/Server/serverprivate.key", message);
						aesKey = util.getKey(message);
						iv = util.decryptPrivateRSA("cryptography_proj/Server/serverprivate.key", encryptediv).getBytes("Latin1");
						message ="Initialized symmetric keys on server";
						streamOut.writeUTF(util.encryptAES(iv, aesKey, message));
						System.out.println(message);
						streamOut.flush();
					} catch (Exception ioe) {
						System.out.println(ioe.getMessage());
						streamOut.writeUTF("Error initializing closing client");
						streamOut.flush();
					}
				}
				
				//Chat loop
				String line = "";
				boolean len = true; //Message length boolean: true if length okay
				while (!done) {	
					try {
						//Receive data
						if (streamIn.available() > 0) {
							String hash = "";

							if (I) {
								hash = streamIn.readUTF(); // Read in hash/MAC first
								if (C && A) {
									try {
										hash = util.decryptAES(iv_MAC, aesKey_MAC, hash);
									} catch (Exception ioe) {
										System.out.println(ioe.getMessage());
										line = ".bye";
									}
								} else if (C && !A) {
									try {
										hash = util.decryptAES(iv, aesKey, hash);
									} catch (Exception ioe) {
										System.out.println(ioe.getMessage());
										line = ".bye";
									}
								}
							}

							System.out.print("Client: ");
							line = streamIn.readUTF();

							if (C && I) {
								if (A) { //decrypt for CIA
									try {
										line = util.decryptAES(iv, aesKey, line);
										integrityMAC.checkIntegrity(line, hash);
									} catch (Exception ioe) {
										System.out.println(ioe.getMessage());
										line = ".bye";
									}
								} else { //decrypt for CI
									try {
										line = util.decryptAES(iv, aesKey, line);
										System.out.println("\n\nReceived the line: " + line);
										System.out.println("Testing signMessage() on " + line + " gives: " + integrity.signMessage(line));
										System.out.println("Testing signMessage() on " + "BABY"+ " gives: " + integrity.signMessage("BABY"));
										System.out.println("Testing signMessage() on " + "BABY"+ " gives: " + integrity.signMessage("BABY"));
										System.out.println("Testing signMessage() on " + "BABY"+ " gives: " + integrity.signMessage("BABY"));
										System.out.println("Testing signMessage() on " + "BABY"+ " gives: " + integrity.signMessage("BABY"));
										integrity.checkIntegrity(line, hash);
									} catch (Exception ioe) {
										System.out.println("THE EXCEPTION WE WANT TO GET RID OF :(");
										System.out.println(ioe.getMessage());
										line = ".bye";
									}
								}
							} else if (C) {
								//decrypt C
								try {
									line = util.decryptAES(iv, aesKey, line);
								} catch (Exception ioe) {
									System.out.println(ioe.getMessage());
									line = ".bye";
								}
                
							} else if (I) { //decrypt for I
								if (A) { //decrypt for IA
									try {
										integrityMAC.checkIntegrity(line, hash);
									} catch (InvalidIntegrityException e) {
										System.out.println(e.getMessage());
										line = ".bye";
										//TODO: Integrity and/or authentication was invalid! How do we want
										//      to handle this? Alert the user? Close the connection?
									}
								} else { //decrypt for I
									try {
										integrity.checkIntegrity(line, hash);
									} catch (InvalidIntegrityException e) {
										System.out.println(e.getMessage());
										line = ".bye";
										//TODO: Integrity was invalid! How do we want to handle this? Alert the user?
										//      Close the connection?
									}
								}
							}	
							System.out.println(line);
							done = line.equals(".bye");
						}
					
						//Send data
						if (console.ready()) {
							String hash = "";
							System.out.print("Server: ");
							line = console.readLine();
							if (line.length() > 100) {
								System.out.println("Message cannot exceed 100 characters");
								len = false;
							} else {
								len = true;
							}
							done = line.equals(".bye");
							
							if (C && I && !done && len) {
								//apply CI
								try {
									if (A) { // Use MAC
										hash = integrityMAC.signMessage(line); // Get data Tag of message
										hash = util.encryptAES(iv_MAC, aesKey_MAC, hash); // Encrypt hash
									} else { // Use hash
										hash = integrity.signMessage(line); // Get hash of message
										hash = util.encryptAES(iv, aesKey, hash); // Encrypt hash
									}
									line = util.encryptAES(iv, aesKey, line); // Encrypt message
								} catch (Exception ioe) {
									System.out.println(ioe.getMessage());
									line = ".bye";
								}

							} else if (C && !done && len) {
								//apply C
								try {
									line = util.encryptAES(iv, aesKey, line);
								} catch (Exception ioe) {
									System.out.println(ioe.getMessage());
									line = ".bye";
								}
								
							} else if (I && !done && len) {
								//apply I
								try{
									if (A) { // Apply integrity with MAC
										hash = integrityMAC.signMessage(line); // Get data Tag of message
										System.out.println("--- " + integrityMAC.checkIntegrity(line, hash));
									} else { // Apply integrity with hash
										hash = integrity.signMessage(line); // Get hash of message
										System.out.println("---" + integrity.checkIntegrity(line, hash));
									}
								} catch (Exception e) {
									System.out.println(e.getMessage());
									line = ".bye";
								}
							}
							
							if (len) {
								if (I) { // Send hash/MAC first
									streamOut.writeUTF(hash);
									streamOut.flush();
								}
								streamOut.writeUTF(line);
								streamOut.flush();
							}
						}
					} catch(IOException ioe) {
						done = true;
					}
				}
				close();
				System.out.println("Disconnected from client");
				System.out.println();
			} //end server running loop
		} catch(IOException ioe) {
			System.out.println(ioe.getMessage()); 
		}
	}
	
	//Open socket parts
	public void open() throws IOException {	 
		streamIn	= new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		streamOut	= new DataOutputStream(socket.getOutputStream());	  
	}
	
	//Create security choices array
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
	public void close() throws IOException {
		if (socket	!= null)	socket.close();
		if (streamIn!= null)	streamIn.close();
	}
	
	public static void main(String args[]) {
		ChatServer server = null;
		if (args.length == 2)
			server = new ChatServer(Integer.parseInt(args[0]), args[1]);
		else if (args.length == 1) 
			server = new ChatServer(Integer.parseInt(args[0]), "null");
		else
			System.out.println("Incorrect command line entry: java ChatServer <port> (<security>)");
	}
}
