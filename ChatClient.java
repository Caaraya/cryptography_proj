import java.net.*;
import java.io.*;

public class ChatClient {  
	private Socket 				socket	 = null;
	private DataInputStream 	streamIn = null;
	private DataInputStream 	console  = null;
	private DataOutputStream	streamOut= null;

	public ChatClient(String serverName, int serverPort, String cia) {
		System.out.println("Establishing connection. Please wait ...");
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
		
		int[] sec = selector(cia);
		
		if ( (sec[0] == 1) && (sec[1] == 1) && (sec[2] == 1) ) {
			//apply all 3 securities to pw check
			System.out.println("C I A");
		} else if ( (sec[0] == 1) && (sec[2] == 1) ) {
			//apply C to pw
			System.out.println("C A");
		} else if ( (sec[1] == 1) && (sec[2] == 1) ) {
			//apply I to pw
			System.out.println("I A");
		} else if (sec[2] == 1) {
			//send pw
			System.out.println("A");
		}
		
		
		while (!line.equals(".bye")) {
			try {  
				if (console.available() > 0) {
					line = console.readLine();
					streamOut.writeUTF(line);
					streamOut.flush();
				}
			
				if (streamIn.available() > 0) {
					line = streamIn.readUTF();
					System.out.println(line);
				}
			} catch(IOException ioe) {
				System.out.println("Sending error: " + ioe.getMessage());
			}
		}
		System.out.println("Disconnected from server.");
	}
	
	public void start() throws IOException {
		streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
		console   = new DataInputStream(System.in);
		streamOut = new DataOutputStream(socket.getOutputStream());
	}
	
	public void stop() {
		try {
			if (console   != null)  console.close();
			if (streamOut != null)  streamOut.close();
			if (socket    != null)  socket.close();
		} catch(IOException ioe) {
			System.out.println("Error closing ...");
		}
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
	
	public static void main(String args[]) {
		ChatClient client = null;
		if (args.length != 3)
			System.out.println("Incorrect command line entry");
		else
			client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
	}
}