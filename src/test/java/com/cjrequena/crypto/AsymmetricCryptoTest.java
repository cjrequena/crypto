package com.cjrequena.crypto;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import static com.cjrequena.crypto.AsymmetricCrypto.generateECKeyPair;
import static com.cjrequena.crypto.AsymmetricCrypto.generateKeyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

@Log4j2
public class AsymmetricCryptoTest {

  @Before
  public void setUp() throws Exception {
  }

  @After
  public void tearDown() throws Exception {
  }

  @Test
  public void generateKeyPairTest() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
    // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
    KeyPair keyPair = generateKeyPair(AsymmetricCrypto.Algorithm.RSA.getAlgorithm(), 1024, new Random().nextLong());
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void generateECKeyPairTest() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
    // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
    KeyPair keyPair = generateECKeyPair("secp256k1");
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void encryptDecryptTest() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, NoSuchPaddingException,
    IllegalBlockSizeException, UnsupportedEncodingException, NoSuchProviderException, InvalidAlgorithmParameterException {
    KeyPair keyPair = generateKeyPair(AsymmetricCrypto.Algorithm.RSA.getAlgorithm(), 1024);
    String classifiedInformation = "CLASSIFIED INFORMATION";
    String encryptedClassifiedInformation = AsymmetricCrypto.encrypt("CLASSIFIED INFORMATION", keyPair.getPublic(), AsymmetricCrypto.Algorithm.RSA.getAlgorithm());
    assertEquals(AsymmetricCrypto.decrypt(encryptedClassifiedInformation, keyPair.getPrivate(), AsymmetricCrypto.Algorithm.RSA.getAlgorithm()), classifiedInformation);
    assertNotEquals(AsymmetricCrypto.decrypt(encryptedClassifiedInformation, keyPair.getPrivate(), AsymmetricCrypto.Algorithm.RSA.getAlgorithm()), classifiedInformation + "DAMAGE");
  }


  private void verifyCreatedKeys(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException {
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    log.debug("Generating key/value pair using {} algorithm ", privateKey.getAlgorithm());

    // Get the bytes of the public and private keys
    byte[] privateKeyBytes = privateKey.getEncoded();
    byte[] publicKeyBytes = publicKey.getEncoded();

    // Get the formats of the encoded bytes
    String formatPrivate = privateKey.getFormat(); // PKCS#8
    String formatPublic = publicKey.getFormat(); // X.509

    log.debug("Private Key : {}", Base64.toBase64String(privateKeyBytes));
    log.debug("Public Key : {}", Base64.toBase64String(publicKeyBytes));

    // The bytes can be converted back to public and private key objects
    KeyFactory keyFactory = KeyFactory.getInstance(keyPair.getPrivate().getAlgorithm());
    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

    assertEquals(privateKey, privateKey2);
    assertEquals(publicKey, publicKey2);
  }
}
