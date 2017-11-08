package cryptography_proj;
import cryptography_proj.ChatUtils;
import javax.crypto.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

/** 
 * The Integrity class uses hashing to ensure that the receiver will be alerted when they
 * receive a message that has been modified accidentally or maliciously. To use this feature,
 * use signMessage to generate a hash, and then send that hash along with the message to the
 * receiver. The receiver can then check the integrity by comparing the hash with their own
 * generated hash.
 */

public class Integrity {

    MessageDigest messageDigest;

    public Integrity() {
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while generating Message Digest with SHA-256", e);
        }
    }

    /**  
     * This method will generate a hash of the message that can be sent along with the message
     * so that the receiver can validate the integrity of the message
     * @param message is the message to be hashed
     * @return the hash
     */
    public String signMessage(String message) {
        byte[] digestEncoded = Base64.getEncoder().encode(message.getBytes());
        digestEncoded = messageDigest.digest(digestEncoded);
        return new String(Base64.getEncoder().encodeToString(digestEncoded));
    }

    /** 
     * This method will verify the integrity of a message hash
     * @return true if the messages have integrity
     * @throws InvalidIntegrityException if message integrity is invalid
     */
    public boolean checkIntegrity(String message, String digest) throws InvalidIntegrityException {

        // Digest is already encoded as Base64 string
        // message is NOT
        // I need to compare the byte arrays of both
        
        String message_dataTag = signMessage(message);
        System.out.println("HASH I RECEIVED: " + digest);
        System.out.println("HASH I MADE: " + message_dataTag);

        byte[] message_dataTag_array = Base64.getEncoder().encode(message_dataTag.getBytes());
        byte[] digestByte = Base64.getEncoder().encode(digest.getBytes());
        boolean integrity = MessageDigest.isEqual(digestByte, message_dataTag_array);

        System.out.println(integrity);
        if (!integrity) {
            throw new InvalidIntegrityException("Message integrity is invalid");
        } else {
            return true;
        }
    }

    // TODO: remove before merge
    public static void main(String[] args) {
      /*  System.out.println("----- Testing: Message has integrity");
        Integrity server = new Integrity();
        Integrity client = new Integrity();
        byte[] hash = server.signMessage("wowzers");
        try {
            boolean check = server.checkIntegrity("wowzers", hash);
            System.out.println("Integrity check: " + check);
        } catch (InvalidIntegrityException e) {
            System.out.println("Integrity check didn't work!");
        }
        System.out.println("Expected result: true\n\n");

        System.out.println("----- Testing: Message is changed in transport (no integrity)");
        server = new Integrity();
        client = new Integrity();
        hash = server.signMessage("wowzers");
        try {
            boolean check = server.checkIntegrity("owzers", hash);
            System.out.println("Integrity check: " + check);
        } catch (InvalidIntegrityException e) {
            System.out.println("Integrity result: false");
            System.out.println("Expected result: false\n\n");
        }*/
    }
}