package aes;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
 
/**
 *  https://www.quickprogrammingtips.com/java/java-asymmetric-encryption-decryption-example-with-rsa.html
 * 
 *  How does RSA and AES differ
 * 
 *  RSA:
 *  
 *  1) It is an asymmetric key algorithm. Meaning, it uses 2 different 
 *     keys (Public key and Private key) for encryption and decryption. 
 *     Public key is available to open world, where as private key is 
 *     possessed by owner.
 *  
 *     1.1) Public Key encryption is used for exchanging data.
 *  
 *     1.2) Privat Key encryption is used for authentication of owner
 *          (digital signatures)
 *  
 *  2) It is stream cipher algorithm. Meaning, entire data is encrypted 
 *     at once, which takes more computational power. Hence it is slow. 
 *     Mainly used for exchanging little information such as symmetric keys.
 *  
 *  3) RSA's strength and weaknesses lies in the factoring large integers.
 *  
 *  AES:
 *  
 *  1) It is a symmetric key algorithm. Meaning, same key is used for both 
 *     encryption and decryption.
 *  
 *  2) It is a 128-block cipher algorithm. Meaning, the data is divided into 
 *     chunks of fixed length data (128 bits). The chunks are processed in 
 *     AES where each round is dependent on output of its predecessor. Large 
 *     data can be encrypted using AES.
 *  
 *  3) AES's strength is in the possible key permutations using Rijndael 
 *     finite field method internally.
 *     
 *  The Rijndael Block Cipher
 *  https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
 *  
 * @author hlasznyedit
 */
public class RSAEncryptionWithAES {
	
	private String       inFileName            = "" ;

	private long         bufLen                = 0 ;
    private byte []      inBuf                 = null ;
    private InputStream  inStream              = null ;
	
	private String       outFileName           = "" ;
    private byte []      outBuf                = null ;
    private OutputStream outStream             = null ;
    
    private String       pathName              = "" ;
    private String       AESkeyFileName        = "key/AESkey.txt" ;
	
    public RSAEncryptionWithAES(String pathName,
    		                    String inFileName, 
		                        String outFileName) throws IOException {

    	this.pathName              = pathName ;
    	this.inFileName            = pathName + inFileName ;
    	this.outFileName           = pathName + outFileName ;
	
    }   //  end of constructor()

    public void encryptAES() throws Exception  {
    	
    	readInfile(this.inFileName) ;

    	String plainText = new String(this.inBuf, "UTF-8"); 
			
        /**
         *  Generate public and private keys using RSA
         */
        Map<String, Object> keys = getRSAKeys();
        
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey  publicKey = (PublicKey) keys.get("public");
 
        /**
         *  First create an AES Key
         */
        String secretAESKeyString = getSecretAESKeyAsString();
 
        /**
         *  Encrypt plain text with AES key
         */
        String encryptedText = encryptTextUsingAES(plainText, secretAESKeyString);
 
        /**
         *  Encrypt AES Key with RSA Private Key
         */
        String encryptedAESKeyString = encryptAESKey(secretAESKeyString, privateKey);
 
        /**
         *  First decrypt the AES Key with RSA Public key
         */
        String decryptedAESKeyString = decryptAESKey(encryptedAESKeyString, publicKey);
        
        this.outBuf = decryptedAESKeyString.getBytes("UTF-8") ;
        
        writeOutfile(this.pathName + AESkeyFileName) ;
 
        /** 
         * Now decrypt data using the decrypted AES key and write into the outfile
         */
        String decryptedText = decryptTextUsingAES(encryptedText, decryptedAESKeyString);
        
        this.outBuf = encryptedText.getBytes("UTF-8") ;
        
        writeOutfile(this.outFileName) ;

    }   //  end of method encryptAES() 
    
	//  =======================================================================
    
    public void decryptAES() throws Exception  {
    	
    	readInfile(this.inFileName) ;

        /**
         *  Encrypted file has been read
         */
        String encryptedText = new String(this.inBuf, "UTF-8"); 
 
        readInfile(this.pathName + AESkeyFileName) ;
        
        String decryptedAESKeyString = new String(this.inBuf, "UTF-8"); 
        
        /** 
         * Now decrypt data using the decrypted AES key and write into the outfile
         */
        String decryptedText = decryptTextUsingAES(encryptedText, decryptedAESKeyString);
        
        this.outBuf = decryptedText.getBytes("UTF-8") ;
        
        writeOutfile(this.outFileName) ;
    	
    }   //  end of method decryptAES() 
    
	//  =======================================================================
    
    /**
     *  Create a new AES key.
     *  
     *  @return the secret AES key as String
     *  @throws Exception may produced by the KeyGenerator
     */
    private String getSecretAESKeyAsString() throws Exception {
    	
        String encodedKey = "" ;

        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            /**
             *  AES key size in number of bits
             */
            generator.init(128); 
            
            SecretKey secKey = generator.generateKey();
            encodedKey       = Base64.getEncoder().encodeToString(secKey.getEncoded());
    	}
        catch (Exception e)
        {
        	e.printStackTrace();
        }
    	
        return encodedKey;

    }   //  end of method getSecretAESKeyAsString()
 
	//  =======================================================================

    /**
     * Encrypt text using AES key
     * @param plainText
     * @param aesKeyString
     * @return the encrypted text
     * @throws Exception may produced by the KeyGenerator
     */
    private String encryptTextUsingAES(String plainText, 
    		                          String aesKeyString) throws Exception {
    	
        byte[] decodedKey     = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 
        		                                  0, 
        		                                  decodedKey.length, "AES") ;
        byte[] byteCipherText = null ;
        
        try {
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
            byteCipherText = aesCipher.doFinal(plainText.getBytes());
    	}
        catch (Exception e)
        {
        	e.printStackTrace();
        }
        
        return Base64.getEncoder().encodeToString(byteCipherText);

    }   //  end of method encryptTextUsingAES()
 
	//  =======================================================================

    /**
     * Decrypt text using AES key
     * @param encryptedText
     * @param aesKeyString
     * @return the decrypted text
     * @throws Exception may produced by the aesChipher
     */
    private String decryptTextUsingAES(String encryptedText, 
    		                           String aesKeyString)  throws Exception {
 
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
 
        byte[] bytePlainText = null ;
        
        try {
            // AES defaults to AES/ECB/PKCS5Padding in Java 7
            Cipher aesCipher = Cipher.getInstance("AES");
            
            aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
            bytePlainText = aesCipher.doFinal(Base64.getDecoder().decode(encryptedText));
    	}
        catch (Exception e)
        {
        	e.printStackTrace();
        }

        return new String(bytePlainText);

    }   //  end of method decryptTextUsingAES()

	//  =======================================================================
 
    /**
     * Get RSA keys. Uses key size of 2048.
     * @return HashMap entry with private and public keys
     * @throws Exception may produced by the KeyGenerator
     */
    private Map<String, Object> getRSAKeys() { //throws Exception {

    	KeyPairGenerator keyPairGenerator = null;
        KeyPair keyPair                   = null;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
    	}
        catch (Exception e)
        {
        	e.printStackTrace();
        }
        
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
 
        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        
        return keys;

    }   //  end of method getRSAKeys()

	//  =======================================================================
 
    /**
     * Decrypt AES Key using RSA public key
     * @param encryptedAESKey
     * @param publicKey
     * @return the decrypted AES key as String
     * @throws Exception may produced by the AES cipher
     */
    private String decryptAESKey(String encryptedAESKey, PublicKey publicKey) throws Exception {
    	
    	Cipher cipher = null ;
    	
        try {
        	cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
    	}
        catch (Exception e)
        {
        	e.printStackTrace();
        }

        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey)));

    }   //  end of method decryptAESKey()
 
	//  =======================================================================

    /**
     * Encrypt AES Key using RSA private key
     * @param plainAESKey
     * @param privateKey
     * @return the encrypted AES key as String
     * @throws Exception may produced by the AES cipher
     */
    private String encryptAESKey(String plainAESKey, PrivateKey privateKey) throws Exception {

    	Cipher cipher = null ;

    	try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
    	}
        catch (Exception e)
        {
        	e.printStackTrace();
        }
        
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainAESKey.getBytes()));
        
    }   //  end of method encryptAESKey()
    

	//  =======================================================================
	
	private void readInfile(String inputFilename) throws IOException  {
		
        try { 
        	
        	File inFile   = new File(inputFilename) ;
        	this.inStream = new FileInputStream(inFile) ;
        	this.bufLen   = inFile.length() ;
        	this.inBuf    = new byte[(int)this.bufLen] ;
        	
        	this.inStream.read(this.inBuf);
        }   
        catch  (IOException e) {
        	
			e.printStackTrace();
        }
        finally {
        	
            if (this.inStream != null) {
            	
            	this.inStream.close();
            }
            
        }   //  end of try block
        
    }   //  end of method readInfile()
    
	//  =======================================================================

	private void writeOutfile(String outputFilename) throws IOException {
		
        try {   
        	File outFile   = new File(outputFilename) ;
        	this.outStream = new FileOutputStream(outFile) ;
        	
        	this.outStream.write(this.outBuf);
        }   
        catch (IOException e) {
        	
			e.printStackTrace();
        }
        finally {
        	
            if (this.outStream != null) {
            	
            	this.outStream.close();
            }
            
        }   //  end of try block
        
    }   //  end of method readInfile()
    
}   //  end of class RSAEncryptionWithAES 
