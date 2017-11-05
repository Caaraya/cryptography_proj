package cryptography_proj;
import cryptography_proj.ChatUtils;
import javax.crypto.*;
import java.security.*;
import java.util.Arrays;

public class Integrity{

    private Mac mac;
    private byte[] tag;
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
            mac = Mac.getInstance("HmacSHA");
            key = macKey;
            mac.init(key);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Key used to initialize Mac was invalid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while generating MAC with HmacSHA1", e);
        }
    }

    // Updates MAC to use a new key
    // Input: Key to initialize MAC with
    public changeKey(Key macKey) {
        mac.reset(macKey);
    }

    //Output: Key used to initialize MAC
    public getKey() {
        return key;
    }

    // Input: message to sign with MAC
    // Output: MAC data tag
    public byte[] SignMessage(String message) {
        try {
            tag = mac.doFinal(message.getBytes());
            return tag;
        } catch (IllegalStateException e) {
            throw new RuntimeException("MAC was not initialized when signing message");
        }
    }

    // Input: MAC data tag to compare with
    // Output: Returns true if MAC tags are identical and therefore integrity is valid.
    //         Otherwise, returns false
    public boolean CheckIntegrity(byte[] tag) {
        return Arrays.equals(this.tag, tag);
    }

    // TODO: remove before merge
    // Testing
    public static void main(String[] args) {

        // create new MAC on client side
        Integrity key = new Integrity();


        byte[] test = key.SignMessage("hello");
        System.out.println(key.CheckIntegrity(test));
        System.out.println(test);
    }
}