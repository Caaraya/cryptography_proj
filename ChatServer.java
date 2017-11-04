package cryptography_proj;
import java.net.*;
import java.io.*;
import cryptography_proj.ChatUtils;

public class ChatServer {  
	private Socket				socket		= null;
	private ServerSocket		server		= null;
	private DataInputStream		streamIn	= null;
	private BufferedReader		console		= new BufferedReader(new InputStreamReader(System.in));
	private DataOutputStream	streamOut	= null;
  private Console 			c 			= System.console();
	private ChatUtils 			util        = new ChatUtils();

	public ChatServer(int port, String sCia) {
		System.out.println("Beginning server");
		//Create server's security array
		int[] sSel = selector(sCia);
		
		if (sSel[2] == 1) {
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
				int[] cSel = selector(cCia);
				
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
				if (sSel[2] == 1 && !done) {
					System.out.println("A");
				}
				
				//Initialize Integrity
				if (sSel[1] == 1 && !done) {
					System.out.println("I");
				}
				
				//Initialize Confidentiality
				if (sSel[0] == 1 && !done) {
					System.out.println("C");
				}
				
				//Chat loop
				String line = "";
				while (!done) {	
					try {
						//Receive data
						if (streamIn.available() > 0) {
							line = streamIn.readUTF();
							if ( (sSel[0] == 1) && (sSel[1] == 1) ) {
								//decrypt CI
							} else if (sSel[0] == 1) {
								//decrypt C
							} else if (sSel[1] == 1) {
								//decrypt I
							}
							System.out.println(line);
							done = line.equals(".bye");
						}
					
						//Send data
						if (console.ready()) {
							line = console.readLine();
							done = line.equals(".bye");
							if ( (sSel[0] == 1) && (sSel[1] == 1) ) {
								//apply CI
							} else if (sSel[0] == 1) {
								//apply C
							} else if (sSel[1] == 1) {
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
	public int[] selector(String sel) {
		int[] choice = new int[3];
		if (sel.contains("C") || sel.contains("c"))
			choice[0] = 1;
		else
			choice[0] = 0;
		
		if (sel.contains("I") || sel.contains("i"))
			choice[1] = 1;
		else
			choice[1] = 0;
		
		if (sel.contains("A") || sel.contains("a"))
			choice[2] = 1;
		else
			choice[2] = 0;
		
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
