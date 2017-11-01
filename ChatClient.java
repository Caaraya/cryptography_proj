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
		
		try {
			streamOut.writeUTF(cia);
		} catch(IOException ioe) {
			System.out.println("Error sending security type: " + ioe.getMessage());
		}
		
		String line = "";
		while (!line.equals(".bye")) {
			try {  
				if (console.available() > 0) {
					line = console.readLine();
					streamOut.writeUTF(line);
					streamOut.flush();
				}
			
				if (streamIn.available() > 0) {
					String text = streamIn.readUTF();
					System.out.println(text);
					if (text.equals(".bye")) {
						line = ".bye";
					}
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
	
	public static void main(String args[]) {
		ChatClient client = null;
		if (args.length != 3)
			System.out.println("Incorrect command line entry");
		else
			client = new ChatClient(args[0], Integer.parseInt(args[1]), args[2]);
	}
}