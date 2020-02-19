/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ctfdx2_proj2_task3rsa;

import java.security.SecureRandom;
import java.security.Security;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileNotFoundException;

import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static sun.security.x509.CertificateAlgorithmId.ALGORITHM;

/**
 *
 * @author k
 */
public class Ctfdx2_proj2_task3RSA {

    /////////////////task 3 RSA FUNCTIONS///////////////////////////////
    public Ctfdx2_proj2_task3RSA(){
        init();
    }
    
    public static void init(){
        Security.addProvider(new BouncyCastleProvider());
    }
    ///////////////Key generator for public and private key pair using 128
    public static KeyPair generateKey() throws NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair key = keyGen.genKeyPair();
        return key;
    }
    ////////////////////////////////////////////////////////////////////////
    ////////File encryption using RSA, currently accepts byte text need to convert
    //to byte text before i send/////////////////////////
    public static byte[] encrypt(byte[] text, PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] cipherText = null;
        //RSA cipher obj
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        //encrypt the plaintext
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return cipherText;
    }
    
    ///////////////////////////////////////////////////////////////////////////
    //////////////File decryption using RSA////////////////////////////////////
    ///////////////using byte decyption need to understand that********
    public static byte[] decrypt(byte[] text, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] decryptedText = null;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        decryptedText = cipher.doFinal(text);
        return decryptedText;
    }
    
    /////trying file methods
    public static void encryptFile(String srcFileName, String destFileName, PublicKey key) throws Exception{
        encryptDecryptFile(srcFileName,destFileName, key, Cipher.ENCRYPT_MODE);
    }
    /////////////now decyption
    public static void decryptFile(String srcFileName, String destFileName, PrivateKey key) throws Exception{
        encryptDecryptFile(srcFileName,destFileName, key, Cipher.DECRYPT_MODE);
    }
    
        public static void encryptDecryptFile(String srcFileName, String destFileName, Key key, int cipherMode) throws Exception
    {
        OutputStream outputWriter = null;
        InputStream inputReader = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            String textLine = null;
            //RSA encryption data size limitations are slightly less than the key modulus size,
            //depending on the actual padding scheme used (e.g. with 1024 bit (128 byte) RSA key,
            //the size limit is 117 bytes for PKCS#1 v 1.5 padding. (http://www.jensign.com/JavaScience/dotnet/RSAEncrypt/)
            byte[] buf = cipherMode == Cipher.ENCRYPT_MODE? new byte[100] : new byte[128];
            int bufl;
            // init the Cipher object for Encryption...
            cipher.init(cipherMode, key);

            // start FileIO
            outputWriter = new FileOutputStream(destFileName);
            inputReader = new FileInputStream(srcFileName);
            while ( (bufl = inputReader.read(buf)) != -1)
            {
                byte[] encText = null;
                if (cipherMode == Cipher.ENCRYPT_MODE)
                {
                      encText = encrypt(copyBytes(buf,bufl),(PublicKey)key);
                }
                else
                {
                    encText = decrypt(copyBytes(buf,bufl),(PrivateKey)key);
                }
                outputWriter.write(encText);
            }
            outputWriter.flush();

        }
        finally
        {
            try
            {
                if (outputWriter != null)
                {
                    outputWriter.close();
                }
                if (inputReader != null)
                {
                    inputReader.close();
                }
            }
            catch (Exception e)
            {
                // do nothing...
            } // end of inner try, catch (Exception)...
        }
    }

    public static byte[] copyBytes(byte[] arr, int length)
    {
        byte[] newArr = null;
        if (arr.length == length)
        {
            newArr = arr;
        }
        else
        {
            newArr = new byte[length];
            for (int i = 0; i < length; i++)
            {
                newArr[i] = (byte) arr[i];
            }
        }
        return newArr;
    }
    
    
    
    
    ////////////start of RSA main function
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, Exception {
        // TODO code application logic here
                
        
    	//Security.addProvider(new BouncyCastleProvider());
    	//BC is the ID for the Bouncy Castle provider;
        if (Security.getProvider("BC") == null){
            System.out.println("Bouncy Castle provider is NOT available");
        }
        else{
            System.out.println("Bouncy Castle provider is available");
        }
        
        ////////////////////file generation function///////////////////////////
        File file = new File("plainTest.txt");
        //Create the file
        if (file.createNewFile()){
            System.out.println("File is created!");
        }else{
            System.out.println("File already exists.");
        }
        //for passing
        
        
        
        /////////////////////output file///////////////////////////////////////
        File fileOut = new File("encrypt.txt");
        //Create the file
        if (fileOut.createNewFile()){
            System.out.println("File is created!");
        }else{
            System.out.println("File already exists.");
        }
        //////////////////checking file /////////////////////
        File filefinal = new File("clearTest.txt");
        //Create the file
        if (filefinal.createNewFile()){
            System.out.println("File is created!");
        }else{
            System.out.println("File already exists.");
        }
        ///////////////////////////////////////////////////////////////////////
        /////////////////////test driver///////////////////////////////////////
        ///generate keys
        KeyPair key = generateKey();
        
        //setting up timers
        //long startTime = System.nanoTime();
        long starterTime = System.nanoTime();
        //Calling encryption on specific files
        encryptFile("plainTest.txt", "encrypt.txt", key.getPublic());
        
        //encryption only timer
        long startTime = System.nanoTime();

        //now decrypting
        decryptFile("encrypt.txt", "clearTest.txt", key.getPrivate());
        
        //stopping timer and output time
        long stopTime = System.nanoTime();
        long elapsedTime = ((stopTime - starterTime)/ 1000000);
        long elapsedTimeB = ((stopTime - startTime)/ 1000000);

        System.out.println("Time takin in milliseocnds: " + elapsedTime );
        System.out.println("Time takin in milliseocnds to decrypt: " + elapsedTimeB );

        System.out.println("Test Done!");
    }
    
}
