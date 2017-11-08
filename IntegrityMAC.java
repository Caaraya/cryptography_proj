package cryptography_proj;
import cryptography_proj.ChatUtils;
import javax.crypto.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/**
The Integrity class uses Message Authentication Codes (MAC) to provide an integrity check when a message
is received. In order to use this, the client and server must share a secret key that is exclusively used
to initialize their MACs. When a sender sends a message, they will sign the message to get a MAC data tag.
This data tag will then be included with the message and sent to the receiver. The receiver will check the
integrity of the message to determine if the information is sound.
*/

public class IntegrityMAC {

    private Mac mac;
    private Key key;

    /**
     * Initializes MAC with an AES key
     */
    public IntegrityMAC() {
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

    /**
     * Initializes MAC with given key
     * @param key Key to initialize MAC
     */
    public IntegrityMAC(String key) {
        try {
            mac = Mac.getInstance("HmacSHA1");
            // get key back into key form
            this.key = ChatUtils.getKey(key);
            mac.init(this.key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Key used to initialize Mac was invalid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while generating MAC with HmacSHA1", e);
        }
    }

    /**
     * This method will create a MAC data tag that can be sent along
     * with its corresponding message in order to provide an integrity check
     * @param message The message that will be signed with MAC
     * @return MAC data tag that corresponds to the message
     */
    public String signMessage(String message) {
        try {
            byte[] dataTag = mac.doFinal(Base64.getEncoder().encode(message.getBytes()));
            for (int i = 0; i < dataTag.length; i++) {
                System.out.print(dataTag[i] + ", ");
            }
            dataTag = Base64.getDecoder().decode(dataTag);
            for (int i = 0; i < dataTag.length; i++) {
                System.out.print(dataTag[i] + ", ");
            }

         //   System.out.println("signMessage: message received: " + message);
           // System.out.println("signMessage returned: " +  Base64.getEncoder().encodeToString(message.getBytes()));
            return Base64.getEncoder().encodeToString(dataTag);
        } catch (IllegalStateException e) {
            throw new RuntimeException("MAC was not initialized when signing message");
        }
    }


    /**
     * This method will check the integrity of a message
     * @param message The message
     * @param dataTag The dataTag that corresponds to the message
     * @return Will return true if integrity check is valid
     * @throws InvalidIntegrityException if the integrity of the message is invalid
     */
    public boolean checkIntegrity(String message, String dataTag) throws InvalidIntegrityException {
        System.out.println("MAC CHECK INTEGRITY");
        System.out.println("Message: " + message);
        System.out.println("DataTag: " + dataTag);

       // byte[] message_dataTag = message.getBytes();
        byte[] dataTag_byte = Base64.getEncoder().encode(dataTag.getBytes());
       // System.out.println("Generated DataTag: " + Base64.getEncoder().encodeToString(mac.doFinal(message_dataTag)));
        boolean integrity = Arrays.equals(Base64.getDecoder().decode(signMessage(message)), dataTag_byte);

        // TODO: Remove when done testing
        // *************************************************
       /* System.out.print("Data Tag Received: ");
        for (int i = 0; i < dataTag.length; i++) {
            System.out.print(dataTag[i] + " ");
        }
        System.out.print("\nData Tag Generated: ");
        for (int i = 0; i < test.length; i++) {
            System.out.print(test[i] + " ");
        }
        System.out.println();
        // *************************************************
        */
        if (!integrity) {
            throw new InvalidIntegrityException("Message integrity is invalid");
        } else {
            return true;
        }
    }

    /**
     * getter method for the key
     * @return Gets key used for MAC algorithm
     */
    public String getKeyString() {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public Key getKey() {
        return key;
    }


    // TODO: remove before merge
    // Testing
    
    public static void main(String[] args) {

        // --------------------- Initial setup ---------------------

        // create new MAC on client side
        IntegrityMAC clientMAC = new IntegrityMAC();
        
        // Send this key to server (ENCRYPT IT)
        String clientKey = clientMAC.getKeyString();

        // Server makes MAC object
        IntegrityMAC serverMAC = new IntegrityMAC(clientKey);


        // --------------------- Example of client sending message to Server ---------------------
        System.out.println("********* Test a message that is signed with the correct key and checked with the correct key");
        // Client types message and signs it
        String clientMessage = "Hello!!";
        String clientDataTag = clientMAC.signMessage(clientMessage);

        System.out.println("Client message sent: " + clientMessage);
        System.out.print("Client data tag sent: ");
        System.out.print(clientDataTag);
        System.out.println();

        // Client sends message and dataTag to Server
        // (Allowed to be unencrypted if Confidentiality is unchecked)
        String serverMessage = clientMessage;
        String messageDataTag = clientDataTag;

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
        IntegrityMAC newClient = new IntegrityMAC();
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

// This exception will be thrown when integrity is invalid
class InvalidIntegrityException extends Exception {
    public InvalidIntegrityException(String message) {
        super(message);
    }
}