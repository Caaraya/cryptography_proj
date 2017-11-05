package cryptography_proj;
import cryptography_proj.ChatUtils;
import javax.crypto.*;
import java.security.*;
import java.util.Arrays;

public class Integrity{

    private Mac mac;
    private Key key;

    // Initialize MAC with a new AES key
    public Integrity() {
        try {
            mac = Mac.getInstance("HmacSHA1");
            key = ChatUtils.makeAESKey();
            mac.init(key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Key used to initialize Mac was invalid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while generating MAC with HmacSHA1", e);
        }
    }

    // Initialize MAC with input key
    // Input: Key to initialize MAC with
    public Integrity(Key key) {
        try {
            mac = Mac.getInstance("HmacSHA1");
            this.key = key;
            mac.init(key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Key used to initialize Mac was invalid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while generating MAC with HmacSHA1", e);
        }
    }

    // Input: message to sign with MAC
    // Output: MAC data tag
    public byte[] signMessage(String message) {
        try {
            return mac.doFinal(message.getBytes());
        } catch (IllegalStateException e) {
            throw new RuntimeException("MAC was not initialized when signing message");
        }
    }

    // TODO: throw exception if it is false
    // Input:
    // Output: Returns true if MAC tags are identical and therefore integrity is valid.
    //         Otherwise, returns false
    public boolean checkIntegrity(String message, byte[] dataTag) throws InvalidIntegrityException {
        byte[] test = mac.doFinal(message.getBytes());
        boolean integrity = Arrays.equals(dataTag, test);

        // TODO: Remove when done testing
        // *************************************************
        System.out.print("Data Tag Received: ");
        for (int i = 0; i < test.length; i++) {
            System.out.print(dataTag[i] + " ");
        }
        System.out.print("\nData Tag Generated: ");
        for (int i = 0; i < test.length; i++) {
            System.out.print(test[i] + " ");
        }
        System.out.println();
        // *************************************************

        if (!integrity) {
            throw new InvalidIntegrityException("Message integrity is invalid");
        } else {
            return true;
        }
    }

    //Output: Key used to initialize MAC
    public Key getKey() {
        return key;
    }

    // TODO: remove before merge
    // Testing
    public static void main(String[] args) {

        // --------------------- Initial setup ---------------------

        // create new MAC on client side
        Integrity clientMAC = new Integrity();
        
        // Send this key to server (ENCRYPT IT)
        Key clientKey = clientMAC.getKey();

        // Server makes MAC object
        Integrity serverMAC = new Integrity(clientKey);

        // --------------------- Example of client sending message to Server ---------------------
        System.out.println("********* Test a message that is signed with the correct key and checked with the correct key");
        // Client types message and signs it
        String clientMessage = "Hello!!";
        byte[] clientDataTag = clientMAC.signMessage(clientMessage);

        System.out.println("Client message sent: " + clientMessage);
        System.out.print("Client data tag sent: ");
        for (int i = 0; i < clientDataTag.length; i++) {
            System.out.print(clientDataTag[i] + " ");
        }
        System.out.println();

        // Client sends message and dataTag to Server
        // (Allowed to be unencrypted if Confidentiality is unchecked)
        String serverMessage = clientMessage;
        byte[] messageDataTag = clientDataTag;

        // Server will check integrity of message by generating MAC data tag of message
        // and then comparing that to the data tag that it received
        System.out.println("Server will check integrity of the message...");
        try {
            System.out.println("checkIntegrity output: " + serverMAC.checkIntegrity(clientMessage, messageDataTag));
        } catch (InvalidIntegrityException e) {
            System.out.println("false");
        }
        System.out.println("Expected result: true\n\n");

        // Testing a message that has been modified (unsound information)
        System.out.println("********* Test a message that is modified in transport");
        System.out.println("Original message: Hello\nNew Message: Helo");
        messageDataTag = clientMAC.signMessage("Hello");
        System.out.println("Server will check integrity of the message...");
        try {
            boolean output = serverMAC.checkIntegrity("Helo", messageDataTag);
            System.out.println("checkIntegrity output: " + output);
        } catch (InvalidIntegrityException e) {
            System.out.println("checkIntegrity output: false");
        }
        System.out.println("Expected result: false\n\n");

        // Testing a message that was encrypted with the wrong key
        System.out.println("********* Test a message that is signed with a different key than the server is expecting");
        Integrity newClient = new Integrity();
        messageDataTag = newClient.signMessage("Hello");
        System.out.println("Message sent: \"Hello\"");
        System.out.println("Server will check integrity of the message...");
        try {
            boolean output = serverMAC.checkIntegrity("Hello", messageDataTag);
            System.out.println("checkIntegrity output: " + output);
        } catch (InvalidIntegrityException e) {
            System.out.println("checkIntegrity output: false");
        }
        System.out.println("Expected result: false\n\n");
    }
}

// Will be thrown when integrity is invalid
class InvalidIntegrityException extends Exception {
    public InvalidIntegrityException(String message) {
        super(message);
    }
}