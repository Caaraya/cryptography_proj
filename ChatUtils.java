
import java.lang.*;
import java.io.*;
import java.security.*;
import java.math.BigInteger;
import java.nio.*;
import javax.crypto.*;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ChatUtils{
    Cipher pkCipher;
    Cipher aesCipher;

    public ChatUtils() throws GeneralSecurityException {
        pkCipher = Cipher.getInstance("RSA");
        aesCipher = Cipher.getInstance("AES");
    }

    public Key makeAESKey() throws NoSuchAlgorithmException
    {
        Key key;
        SecureRandom rand = new SecureRandom();
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, rand);
        return generator.generateKey();
    }

    private PrivateKey getPrivateKey(String loc)
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

    private PublicKey getPublicKey(String loc)
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

    
    public static String encryptPublicRSA(String path, String msg, Cipher pkCipher) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        PublicKey key = getPublicKey(path);
        byte[] str = null;
        if (key == null) return "";
        pkCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] reCipherBytes = Base64.getDecoder().decode(msg);
        str = pkCipher.doFinal(reCipherBytes);
        return Base64.getEncoder().encodeToString(str);
    }

    public static String decryptPrivateRSA(String path, String msg, Cipher pkCipher) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException
    {
        PrivateKey key = getPrivateKey(path);
        byte[] str = null;
        if (key == null) return "";
        pkCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] reCipherBytes = Base64.getDecoder().decode(msg);
        str = pkCipher.doFinal(reCipherBytes);
        return Base64.getEncoder().encodeToString(str);
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