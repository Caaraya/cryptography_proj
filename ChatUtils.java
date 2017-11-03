package assignment3;

import java.lang.*;
import java.io.*;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.security.PrivateKey;

public class ChatUtils{

    private PrivateKey getPrivateFromKeyStore(String path, String passwd, String alias)
    {
        PrivateKey key = null;
        
        return key;
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