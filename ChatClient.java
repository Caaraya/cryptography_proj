package cryptography_proj;
import java.net.*;
import java.io.*;
import cryptography_proj.ChatUtils;

public class ChatClient {  
	private Socket 				socket	 = null;
	private DataInputStream 	streamIn = null;
	private BufferedReader	 	console  = null;
	private DataOutputStream	streamOut= null;

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
		int[] sec = selector(cia);
		
		//Apply Authentication
		if ( (sec[0] == 1) && (sec[1] == 1) && (sec[2] == 1) ) {
			//apply all 3 securities to pw check
		} else if ( (sec[0] == 1) && (sec[2] == 1) ) {
			//apply C to pw
		} else if ( (sec[1] == 1) && (sec[2] == 1) ) {
			//apply I to pw
		} else if (sec[2] == 1) {
			//send pw
		}
		
		//Chat loop
		while (!line.equals(".bye")) {
			try {  
				//Data to send
				if (console.ready()) { 
					line = console.readLine();
					if ( (sec[0]== 1) && (sec[1] == 1) ) {
						//apply CI
					} else if (sec[0] == 1) {
						//apply C
					} else if (sec[1] == 1) {
						//apply I
					}		
					streamOut.writeUTF(line);
					streamOut.flush();
				}
				//Data to receive
				if (streamIn.available() > 0) {
					line = streamIn.readUTF();
					if ( (sec[0]== 1) && (sec[1] == 1) ) {
						//decrypt for CI
					} else if (sec[0] == 1) {
						//decrypt for C
					} else if (sec[1] == 1) {
						//decrypt for I
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
		if (args.length != 3)
			System.out.println("Incorrect command line entry: java ChatClient <connection> <port> <security>");
		else
			client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
	}
}