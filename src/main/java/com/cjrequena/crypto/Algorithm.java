package com.cjrequena.crypto;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 * @author cjrequena
 *
 */
public enum Algorithm {
  AES("AES"), // Symmetric
  DES("DES"), // Symmetric
  DH("DH"),   // Asymmetric
  EC("EC"),   // Asymmetric
  RSA("RSA"); // Asymmetric

  private String algorithm;

  /**
   *
   * @param algorithm
   */
  Algorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  /**
   *
   * @return
   */
  public String getAlgorithm() {
    return this.algorithm;
  }
}
