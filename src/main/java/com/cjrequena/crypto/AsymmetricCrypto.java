package com.cjrequena.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
public class AsymmetricCrypto {

  /**
   *
   */
  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   * <p>
   * Creates an asymmetric  key pair.
   * </p>
   * <br>
   * Asymmetric keys are used for asymmetric encryption algorithms. Asymmetric encryption algorithms use one key for encryption, and another for decryption. The public key - private
   * key encryption algorithms are examples of asymmetric encryption algorithms.
   *
   * @param algorithm
   * @param size
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   */
  public static KeyPair generateKeyPair(String algorithm, int size) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    keyPairGenerator.initialize(size, new SecureRandom());
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    return keyPair;
  }

  /**
   * <p>
   * Creates an asymmetric  key pair.
   * </p>
   * <br>
   * Asymmetric keys are used for asymmetric encryption algorithms. Asymmetric encryption algorithms use one key for encryption, and another for decryption. The public key - private
   * key encryption algorithms are examples of asymmetric encryption algorithms.
   *
   * @param algorithm
   * @param size
   * @param seed
   * @return
   * @throws Exception
   */
  public static KeyPair generateKeyPair(String algorithm, int size, long seed) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.setSeed(seed);
    keyPairGenerator.initialize(size, new SecureRandom());
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    return keyPair;
  }

//  /**
//   *
//   * @param spec
//   * @return
//   * @throws NoSuchAlgorithmException
//   * @throws NoSuchProviderException
//   * @throws InvalidAlgorithmParameterException
//   */
//  public static KeyPair generateECKeyPair(String spec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
//    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Algorithm.EC.getAlgorithm());
//    ECGenParameterSpec parameterSpec = new ECGenParameterSpec(spec);
//    //ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(spec);
//    keyGen.initialize(parameterSpec, new SecureRandom());
//    KeyPair keyPair = keyGen.generateKeyPair();
//    return keyPair;
//  }

  /**
   *
   * @param data
   * @param key
   * @return
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public static String encrypt(String data, Key key, String algorithm)
    throws InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key);
    AlgorithmParameters params = cipher.getParameters();
    byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
    return Base64.toBase64String(encryptedData);
  }

  /**
   *
   * @param data
   * @param key
   * @return
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public static String decrypt(String data, Key key, String keyAlgorithm)
    throws InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    Cipher cipher = Cipher.getInstance(keyAlgorithm);
    cipher.init(Cipher.DECRYPT_MODE, key);
    AlgorithmParameters params = cipher.getParameters();
    byte[] decodedData = Base64.decode(data.getBytes("UTF-8"));
    byte[] decryptedData = cipher.doFinal(decodedData);
    return new String(decryptedData);
  }

}
