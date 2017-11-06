import java.lang.*;
import java.io.*;
import java.security.*;
import java.math.BigInteger;
import java.nio.*;
import javax.crypto.*;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class DigestGenPass
{
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

    public static String encryptAES(byte[] iv, SecretKey key, String msg) throws Exception
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
    public static String decryptAES(byte[] iv, SecretKey key, String msg) throws Exception
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
    public static String encryptPublicRSAALT(String path, String msg) throws Exception
    {
        Cipher pkCipher = Cipher.getInstance("RSA");
        PublicKey key = getPublicKey(path);
        byte[] str = null;
        if (key == null) return "";
        pkCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] reCipherBytes = msg.getBytes("Latin1");
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

    public static String decryptPrivateRSAALT(String path, String msg) throws Exception
    {
        Cipher pkCipher = Cipher.getInstance("RSA");
        PrivateKey key = getPrivateKey(path);
        byte[] str = null;
        if (key == null) return "";
        pkCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] reCipherBytes = Base64.getDecoder().decode(msg);
        str = pkCipher.doFinal(reCipherBytes);
        return new String(str, "Latin1");
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
    public static SecretKey getKey(String key)
    {
        SecretKey aeskey = null;
        try{
            byte[] data = key.getBytes("Latin1");
            System.out.println(data.length);
            System.out.println(new String(data, "Latin1"));
            aeskey = new SecretKeySpec(data, 0, data.length, "AES");
        }
        catch (Exception ex){
            System.out.println("we have an exception");
            System.out.println(ex.getMessage());
        }
       
        return aeskey;
    }

    public static void main(String[] args)
    {
        try{
            String result = encryptPublicRSAALT("Client/serverpublic.key", "ping client for encryption");
            System.out.println(result);
            result = decryptPrivateRSAALT("Server/serverprivate.key", result);
            System.out.println(result);
            Key aeskey = makeAESKey();
            System.out.println(aeskey.getEncoded().length);
            System.out.println(new String(aeskey.getEncoded(), "Latin1"));
            String encrypted = encryptPublicRSAALT("Client/serverpublic.key", new String(aeskey.getEncoded(), "Latin1"));
            String decrypted = decryptPrivateRSAALT("Server/serverprivate.key", encrypted);
            System.out.println(decrypted);
            Key aesKey = getKey(decrypted);
            byte[] iv = generateIV();
            System.out.println(new String(iv, "Latin1"));
            encrypted = encryptPublicRSAALT("Client/serverpublic.key", new String(iv, "Latin1"));
            decrypted = decryptPrivateRSAALT("Server/serverprivate.key", encrypted);
            System.out.println(decrypted);
            System.out.println(iv.length);
            System.out.println(decrypted.getBytes().length);

            result = encryptAES(iv, aeskey, "symmetric encryption");
            System.out.println(result.getBytes("Latin1").length);
            result = decryptAES(decrypted.getBytes(), aesKey, result);
            System.out.println(new String(aeskey.getEncoded(), "Latin1"));
            System.out.println(new String(aesKey.getEncoded(), "Latin1"));
            System.out.println(result);
        }
        catch(Exception ioe){
            System.out.println(ioe.getMessage());
        }
    }
}