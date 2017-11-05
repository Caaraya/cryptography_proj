package cryptography_proj;
import java.net.*;
import java.io.*;
import cryptography_proj.ChatUtils;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class ChatServer {  
	private Socket				socket		= null;
	private ServerSocket		server		= null;
	private DataInputStream		streamIn	= null;

	private BufferedReader		console		= new BufferedReader(new InputStreamReader(System.in));
	private DataOutputStream	streamOut	= null;
  private Console 			c 			= System.console();

	private ChatUtils 			util        = new ChatUtils();

	private Integrity integrity;
	private IntegrityMAC integrityMAC;

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
				if (A) {
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
				if(I && A) {
					try {
						// TODO: remove this inner try catch block when done with placeholder
						try {
							Key key = ChatUtils.makeAESKey(); //TODO: This is just a placeholder till I figure out how to receive they key
							integrityMAC = new IntegrityMAC(key);
						} catch (NoSuchAlgorithmException e) {
							// TODO: remove
						}
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
				if (C) {
					
				}
				
				//Chat loop
				String line = "";
				while (!done) {	
					try {
						//Receive data
						if (streamIn.available() > 0) {
							line = streamIn.readUTF();
							if (C && I) {
								if (A) { //decrypt for CIA
									//TODO: ADD CONFIDENTIALITY DECRYPTING!! ***
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
									//TODO: ADD CONFIDENTIALITY DECRYPTING!! ***
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
								//decrypt C
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
							done = line.equals(".bye");
						}
					
						//Send data
						if (console.ready()) {
							line = console.readLine();
							done = line.equals(".bye");
							if ( (C) && (I) ) {
								//apply CI
							} else if (C) {
								//apply C
							} else if (I) {
								//apply I
							}
							
							streamOut.writeUTF(line);
							streamOut.flush();
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
		if (args.length != 2)
			System.out.println("Incorrect command line entry: java ChatServer <port> <security>");
		else
			server = new ChatServer(Integer.parseInt(args[0]), args[1]);
	}
}
