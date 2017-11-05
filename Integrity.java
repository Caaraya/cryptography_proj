package cryptography_proj;
import cryptography_proj.ChatUtils;
import javax.crypto.*;
import java.security.*;
import java.util.Arrays;

public class Integrity{

    private Mac mac;
    private byte[] tag;

    // Generates MAC
    public Integrity() {
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(ChatUtils.makeAESKey());
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Exception while making MAC data key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Exception while generating AES key", e);
        }
    }

    // Returns a MAC data tag
    public byte[] SignMessage(String message) {
        try {
            tag = mac.doFinal(message.getBytes());
            return tag;
        } catch (IllegalStateException e) {
            throw new RuntimeException("MAC was not initialized when signing message");
        }
    }

    // Compares two MAC
    public boolean CheckIntegrity(byte[] tag) {
        return Arrays.equals(this.tag, tag);
    }

    // testing
    public static void main(String[] args) {
        Integrity key = new Integrity();
        byte[] test = key.SignMessage("hello");
        System.out.println(key.CheckIntegrity(test));
        System.out.println(test);
    }
}