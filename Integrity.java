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
    public Integrity(Key macKey) {
        try{
            mac = Mac.getInstance("HmacSHA1");
            key = macKey;
            mac.init(key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Key used to initialize Mac was invalid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while generating MAC with HmacSHA1", e);
        }
    }
/*
    // Updates MAC to use a new key
    // Input: Key to initialize MAC with
    public void changeKey(Key macKey) {
        mac.reset(macKey);
    }
*/
    //Output: Key used to initialize MAC
    public Key getKey() {
        return key;
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

    // Input: Compar data Tag of message with inputted dataTag
    // Output: Returns true if MAC tags are identical and therefore integrity is valid.
    //         Otherwise, returns false
    public boolean checkIntegrity(String message, byte[] dataTag) {
        return Arrays.equals(dataTag, mac.doFinal(message.getBytes()));
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

        // --------------------- Message sharing ---------------------

        // Client types message and signs it
        String clientMessage = "Hello!!";
        byte[] clientDataTag = clientMAC.signMessage(clientMessage);

        // Client sends message and dataTag to Server
        // (Allowed to be unencrypted if Confidentiality is unchecked)
        String serverMessage = clientMessage;
        byte[] messageDataTag = clientDataTag;

        // Server will check integrity of message by generating MAC data tag of message
        // and then comparing that to the data tag that it received
        // boolean output = serverMac.checkIntegrity(clientMessage, messageDataTag);
    }
}