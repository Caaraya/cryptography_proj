import java.net.*;
import java.io.*;

public class ChatServer {  
	private Socket				socket		= null;
	private ServerSocket		server		= null;
	private DataInputStream		streamIn	= null;
	private DataInputStream		console		= null;
	private DataOutputStream	streamOut	= null;

	public ChatServer(int port, String sCia) {  
		try {
			System.out.println("Binding to port " + port + ", please wait	...");
			server = new ServerSocket(port);
			System.out.println("Server started: " + server);
			
			//put something here to have the rest loop indefinately
			while(true) {
				System.out.println("Waiting for a client ...");
				socket = server.accept();
				System.out.println("Client found: " + socket);
				open();
				
				int[] sSel = selector(sCia);
				String cCia = streamIn.readUTF();
				int[] cSel = selector(cCia);
				
				boolean done = false;
				
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
				
				if ( (sSel[0] == 1) && (sSel[1] == 1) && (sSel[2] == 1) ) {
					//receive fully secured pw
				} else if ( (sSel[0] == 1) && (sSel[2] == 1) ) {
					//receive C'd pw
				} else if ( (sSel[1] == 1) && (sSel[2] == 1) ) {
					//receive I'd pw
				} else if (sSel[2] == 1) {
					//receive pw
				}
				
				String line = "";
				while (!done) {	
					try {
						if (streamIn.available() >0) {
							line = streamIn.readUTF();
							System.out.println(line);
							done = line.equals(".bye");
						}
					
						if (console.available() >0) {
							line = console.readLine();
							streamOut.writeUTF(line);
							streamOut.flush();
							done = line.equals(".bye");
						}
					} catch(IOException ioe) {
						done = true;
					}
				}
				close();
				System.out.println("Disconnected from client");
				System.out.println();
			}
		} catch(IOException ioe) {
			System.out.println(ioe.getMessage()); 
		}
	}
	
	public void open() throws IOException {	 
		streamIn	= new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		console		= new DataInputStream(System.in);
		streamOut	= new DataOutputStream(socket.getOutputStream());	  
	}
	
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
	
	public void close() throws IOException {
		if (socket	!= null)	socket.close();
		if (streamIn!= null)	streamIn.close();
	}
	
	public static void main(String args[]) {
		ChatServer server = null;
		if (args.length != 2)
			System.out.println("Incorrect command line entry");
		else
			server = new ChatServer(Integer.parseInt(args[0]), args[1]);
	}
}