
import java.lang.*;
import java.io.*;
import java.security.*;
import java.math.BigInteger;
import java.nio.*;
import javax.crypto.*;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ChatUtils{

    private static PrivateKey getPrivateKey(String loc)
    {
        PrivateKey privateKey = null;
        try{
            File path = new File(loc);
            FileInputStream inputStream = new FileInputStream(path);
            int pathlen = (int)path.length();
            byte[] data = new byte[pathlen];
            inputStream.read(data, 0, pathlen);
            KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
            privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(data));
        }
        catch (Exception ex){
            System.out.println(ex.getMessage());
        }
       
        return privateKey;
    }

    private static PublicKey getPublicKey(String loc)
    {
        PublicKey key = null;
        try 
        {
            File path = new File(loc);
            FileInputStream inputStream = new FileInputStream(path);
            int pathlen = (int)path.length();
            byte[] data = new byte[pathlen];
            inputStream.read(data, 0, pathlen);
            KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
            key = kf.generatePublic(new X509EncodedKeySpec(data));
        }
        catch (Exception ex){
            System.out.println(ex.getMessage());
        }
        return key;
    }

    public static String encryptAES(Key key, String msg) throws 
    NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        Cipher aeCipher = Cipher.getInstance("AES");
        byte[] str = null;
        if (key == null) return "";
        aeCipher.init(Cipher.ENCRYPT_MODE, key);
        str = aeCipher.doFinal(msg.getBytes());
        return new String(str);
    }

    public static String decryptAES(Key key, String msg) throws
    NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        Cipher aeCipher = Cipher.getInstance("AES");
        byte[] str = null;
        if (key == null) return "";
        aeCipher.init(Cipher.DECRYPT_MODE, key);
        str = aeCipher.doFinal(msg.getBytes());
        return new String (str);
    }
    
    public static String encryptPublicRSA(String path, String msg) throws 
    NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        Cipher pkCipher = Cipher.getInstance("RSA");
        PublicKey key = getPublicKey(path);
        byte[] str = null;
        if (key == null) return "";
        pkCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] reCipherBytes = Base64.getDecoder().decode(msg);
        str = pkCipher.doFinal(reCipherBytes);
        return Base64.getEncoder().encodeToString(str);
    }

    public static String decryptPrivateRSA(String path, String msg) throws 
    NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, BadPaddingException
    {
        Cipher pkCipher = Cipher.getInstance("RSA");
        PrivateKey key = getPrivateKey(path);
        byte[] str = null;
        if (key == null) return "";
        pkCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] reCipherBytes = Base64.getDecoder().decode(msg);
        str = pkCipher.doFinal(reCipherBytes);
        return Base64.getEncoder().encodeToString(str);
    }
    public static Key makeAESKey() throws NoSuchAlgorithmException
    {
        Key key;
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }
    public String hashpass(String plainpass){
        String str;
        try{
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte [] md5sum = md.digest(plainpass.getBytes());
            str = String.format("%032X", new BigInteger(1, md5sum));
        } catch (Exception ex){
            str = ex.getMessage();
        }
        return str;
    }
}