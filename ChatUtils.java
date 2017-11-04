package cryptography_proj;
import java.lang.*;
import java.io.*;
import java.security.*;
import java.math.BigInteger;
import java.nio.*;
import javax.crypto.*;
import java.util.*;
import javax.crypto.spec.IvParameterSpec;

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

    public static String encryptAES(byte[] iv, Key key, String msg) throws Exception
    {
        Cipher aeCipher = Cipher.getInstance( key.getAlgorithm() + "/CBC/PKCS5Padding" );
        byte[] str = null;
        if (key == null) return "";
        aeCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        str = aeCipher.doFinal(msg.getBytes());
        return new String(str);
    }

    public static String decryptAES(byte[] iv, Key key, String msg) throws Exception
    {
        Cipher aeCipher = Cipher.getInstance( key.getAlgorithm() + "/CBC/PKCS5Padding" );
        byte[] str = null;
        if (key == null) return "";
        aeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        str = aeCipher.doFinal(msg.getBytes());
        return new String (str);
    }
    
    public static String encryptPublicRSA(String path, String msg) throws Exception
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

    public static String decryptPrivateRSA(String path, String msg) throws Exception
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
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        return generator.generateKey();
    }

    public static byte [] generateIV() {
        SecureRandom rand = new SecureRandom();
        byte [] iv = new byte [16];
        rand.nextBytes(iv);
        return iv;
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

    public String readFileAsString(String filePath) throws IOException {
        StringBuffer fileData = new StringBuffer();
        BufferedReader reader = new BufferedReader(
                new FileReader(filePath));
        char[] buf = new char[1024];
        int numRead=0;
        while((numRead=reader.read(buf)) != -1){
            String readData = String.valueOf(buf, 0, numRead);
            fileData.append(readData);
        }
        reader.close();
        return fileData.toString();
    }
}