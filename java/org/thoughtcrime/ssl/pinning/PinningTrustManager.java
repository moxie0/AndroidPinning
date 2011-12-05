package org.thoughtcrime.ssl.pinning;

/*
 * Copyright (c) 2011 Moxie Marlinspike <moxie@thoughtcrime.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * If you need this to be something other than GPL, send me an email.
 */

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A TrustManager implementation that enforces Certificate "pins."
 *.
 * <p>
 * PinningTrustManager is layered on top of the system's default TrustManager,
 * such that the system continues to validate CA signatures for SSL connections
 * as usual.  Additionally, however, PinningTrustManager will enforce certificate
 * constraints on the validated certificate chain.  Specifically, it
 * will ensure that one of an arbitrary number of specified SubjectPublicKeyInfos 
 * appears somewhere in the valid certificate chain.
 * </p>
 * <p>
 * To use:
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[1];
 * trustManagers[0]             = new PinningTrustManager(new String[] {"f30012bbc18c231ac1a44b788e410ce754182513"});
 * 
 * SSLContext sslContext = SSLContext.getInstance("TLS");
 * sslContext.init(null, trustManagers, null);
 *	
 * HttpsURLConnection urlConnection = (HttpsURLConnection)new URL("https://encrypted.google.com/").openConnection();
 * urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());
	    	  
 * InputStream in = urlConnection.getInputStream();
 * </pre>
 * </p>
 * 
 * @author Moxie Marlinspike
 */

public class PinningTrustManager implements X509TrustManager {

  private final TrustManager[] systemTrustManagers;
  private final SystemKeyStore systemKeyStore;
	
  private final List<byte[]> pins = new LinkedList<byte[]>();

  /**
   * Constructs a PinningTrustManager with a set of valid pins.
   *
   * @param pins  A collection of pins to match a seen certificate
   * chain against.  A pin is a hex-encoded hash of a X.509 certificate's
   * SubjectPublicKeyInfo.  A pin can be generated using the provided pin.py
   * script: python ./pin.py certificate_file.pem
   *
   * @throws CertificateException If the system trust store can't be initialized.
   */

  public PinningTrustManager(String[] pins) throws CertificateException {
    this.systemTrustManagers = this.initializeSystemTrustManagers();
    this.systemKeyStore      = new SystemKeyStore();
		
    for (String pin : pins)
      this.pins.add(hexStringToByteArray(pin));
  }
	
  private TrustManager[] initializeSystemTrustManagers() throws CertificateException {
    try {
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
      tmf.init((KeyStore)null);
			
      return tmf.getTrustManagers();
    } catch (NoSuchAlgorithmException nsae) {
      throw new CertificateException(nsae);
    } catch (KeyStoreException e) {
      throw new CertificateException(e);
    } 
  }
   	
  private boolean isValidPin(X509Certificate certificate) throws CertificateException {
    try {
      byte[] spki          = certificate.getPublicKey().getEncoded();	        	
      MessageDigest digest = MessageDigest.getInstance("SHA1");
      byte[] pin           = digest.digest(spki);
        	
      for (byte[] validPin : this.pins) {
	if (Arrays.equals(validPin, pin))
	  return true;
      }
        		        	
      return false;
    } catch (NoSuchAlgorithmException nsae) {
      throw new CertificateException(nsae);
    }
  }
	
  public void checkClientTrusted(X509Certificate[] chain, String authType)
    throws CertificateException 
  {
    throw new CertificateException("Client certificates not supported!");
  }

  public void checkServerTrusted(X509Certificate[] chain, String authType)
    throws CertificateException 
  {
    for (TrustManager systemTrustManager : systemTrustManagers) {
      ((X509TrustManager)systemTrustManager).checkServerTrusted(chain, authType);				
    }
		
    X509Certificate anchor = this.systemKeyStore.getTrustRoot(chain);
		
    for (X509Certificate certificate : chain) {
      if (isValidPin(certificate))
	return;
    }
		
    if (anchor != null && isValidPin(anchor))
      return;
		
    throw new CertificateException("No valid Pins found in Certificate Chain!");
  }

  public X509Certificate[] getAcceptedIssuers() {
    return null;
  }

  private byte[] hexStringToByteArray(String s) {
    int len     = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
			    + Character.digit(s.charAt(i+1), 16));
    }
    return data;
  }
	
  private class SystemKeyStore {
    private final PKIXParameters parameters;
    private final CertPathValidator validator;
    private final CertificateFactory certificateFactory;
    	
    public SystemKeyStore() throws CertificateException {
      try {
	this.parameters         = this.getPkixParameters();
	this.certificateFactory = CertificateFactory.getInstance("X509");
	this.validator          = CertPathValidator.getInstance("PKIX");
      } catch (NoSuchAlgorithmException nsae) {
	throw new CertificateException(nsae);
      }
    }
    	
    public X509Certificate getTrustRoot(X509Certificate[] chain) throws CertificateException {
      try {
	CertPath certPath                  = certificateFactory.generateCertPath(Arrays.asList(chain));
	PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)validator.validate(certPath, this.parameters);
				
	if (result == null) return null;
	else				return result.getTrustAnchor().getTrustedCert();
      } catch (CertPathValidatorException e) {
	return null;
      } catch (InvalidAlgorithmParameterException e) {
	throw new CertificateException(e);
      }
    }
    	
    private PKIXParameters getPkixParameters() {
      try {
	KeyStore trustStore          = this.getTrustStore();
	HashSet<TrustAnchor> trusted = new HashSet<TrustAnchor>();
	            
	for (Enumeration<String> aliases = trustStore.aliases(); aliases.hasMoreElements();) {
	  String alias         = aliases.nextElement();
	  X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
	                
	  if (cert != null)
	    trusted.add(new TrustAnchor(cert, null));
	}
	            
	PKIXParameters parameters = new PKIXParameters(trusted);
	parameters.setRevocationEnabled(false);
	
	return parameters;
      } catch (InvalidAlgorithmParameterException e) {
	throw new AssertionError(e);
      } catch (KeyStoreException e) {
	throw new AssertionError(e);
      }
    }

    private KeyStore getTrustStore() {
      try {
	KeyStore trustStore = KeyStore.getInstance("BKS");
	    			    		
	trustStore.load(new BufferedInputStream(new FileInputStream(getTrustStorePath())),
			getTrustStorePassword().toCharArray());
	    		
	return trustStore;
      } catch (NoSuchAlgorithmException nsae) {
	throw new AssertionError(nsae);
      } catch (KeyStoreException e) {
	throw new AssertionError(e);
      } catch (CertificateException e) {
	throw new AssertionError(e);
      } catch (FileNotFoundException e) {
	throw new AssertionError(e);
      } catch (IOException e) {
	throw new AssertionError(e);
      }
    }
    	
    private String getTrustStorePath() {
      String path = System.getProperty("javax.net.ssl.trustStore");
    		
      if (path == null) {
	path = System.getProperty("java.home") + 
	  File.separator + "etc"             + 
	  File.separator + "security"        + 
	  File.separator + "cacerts.bks";
      }

      return path;
    }
    	
    private String getTrustStorePassword() {
      String password = System.getProperty("javax.net.ssl.trustStorePassword");
    		
      if (password == null)
	password = "changeit";
    		
      return password;
    }
  }
}
