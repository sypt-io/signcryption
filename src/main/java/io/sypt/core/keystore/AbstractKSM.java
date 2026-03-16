package io.sypt.core.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.keystore.exception.KSMException;

/**
 * Manager to explore and find {@link PublicKey} / {@link PrivateKey} from a PKCS12 {@link KeyStore} using its data
 * @author tazouxme
 */
public abstract class AbstractKSM implements KSM {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	/**
	 * KeyStore containing Public / Private keys
	 */
	private final KeyStore keyStore;
	
	/**
	 * Flag to ensure that the Keystore has not been closed
	 */
	private final AtomicBoolean closed = new AtomicBoolean(false);
	
	/**
	 * Container for alias and pass of the Private Key
	 */
	private final KeyData keyData;
	
	/**
	 * Container for the PrivateKey password
	 */
	private final char[] keyPassword;
	
	/**
	 * Security Provider. Default is {@link BouncyCastleProvider} (BC)
	 */
	private final String provider;
	
	/**
	 * Construct a new {@link AbstractKSM} using the default KeyStore.getInstance()
	 * @param keystorePassword
	 * @param keyData
	 * @throws KSMException 
	 */
	protected AbstractKSM(char[] keystorePassword, KeyData keyData) {
		this(keystorePassword, keyData, null);
	}
	
	/**
	 * Construct a new {@link AbstractKSM}
	 * @param keystorePassword
	 * @param keyData
	 * @param provider
	 * @throws KSMException 
	 */
	protected AbstractKSM(char[] keystorePassword, KeyData keyData, String provider) {
		if (keystorePassword == null || keyData == null || keyData.pass() == null) {
            throw new IllegalArgumentException("Keystore password and KeyData are required");
        }
		
		this.keyData = keyData;
		this.keyPassword = keyData.pass().clone();
		this.provider = provider;
		
		char[] pwd = keystorePassword.clone();
        try {
            this.keyStore = loadAndInitialize(pwd);
        } catch (KSMException e) {
        	log.warn("Unable to load keystore with alias {}", keyData.alias());
			throw new IllegalArgumentException("Unable to load keystore with alias " + keyData.alias(), e);
		} finally {
            Arrays.fill(pwd, '\0');
        }
	}

	/**
	 * Extract the {@link KeyStore} using the data of the KeyStore and its initialized password
	 * @return Found {@link KeyStore}
	 * @throws KSMException
	 */
	private KeyStore loadAndInitialize(char[] pwd) throws KSMException {
		try (InputStream is = getInputStream()) {
            if (is == null) {
                throw new KSMException("InputStream is null, cannot load KeyStore");
            }
            
            KeyStore ks = StringUtils.isBlank(provider) ? KeyStore.getInstance(KSM.KEY_STORE_TYPE) : KeyStore.getInstance(KSM.KEY_STORE_TYPE, provider);
            ks.load(is, pwd);
            log.info("KeyStore loaded and initialized for alias: {}", keyData.alias());
            return ks;
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new KSMException("Unable to get the KeyStore", e);
        }
	}
	
	@Override
	public KeyStore getKeyStore() throws KSMException {
		ensureNotClosed();
        return keyStore;
	}
	
	@Override
	public Certificate getCertificate() throws KSMException {
		ensureNotClosed();
        try {
            return getKeyStore().getCertificate(keyData.alias());
        } catch (KeyStoreException e) {
            throw new KSMException("Unable to get the Certificate", e);
        }
	}
	
	@Override
	public Certificate[] getCertificateChain() throws KSMException {
		ensureNotClosed();
        try {
            return getKeyStore().getCertificateChain(keyData.alias());
        } catch (KeyStoreException e) {
            throw new KSMException("Unable to get the Certificate chain", e);
        }
	}

	@Override
	public PublicKey getPublicKey() throws KSMException {
		Certificate cert = getCertificate();
        if (cert == null) {
            throw new KSMException("No certificate found for alias: " + keyData.alias());
        }
        return cert.getPublicKey();
	}
	
	@Override
	public PrivateKey getPrivateKey() throws KSMException {
		ensureNotClosed();
        char[] pwd = keyPassword.clone();
        try {
            return (PrivateKey) getKeyStore().getKey(keyData.alias(), pwd);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new KSMException("Unable to get the PrivateKey", e);
        } finally {
            Arrays.fill(pwd, '\0');
        }
	}
	
	@Override
	public KeyData getKeyData() {
		return keyData;
	}
	
	@Override
	public String getProvider() {
		return provider;
	}
	
	@Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            Arrays.fill(keyPassword, '\0');
            log.debug("KeyStoreManager closed and secrets wiped for alias: {}", keyData.alias());
        }
    }
	
	private void ensureNotClosed() throws KSMException {
        if (closed.get()) {
            throw new KSMException("Manager is closed. Secrets have been wiped.");
        }
    }
	
	protected abstract InputStream getInputStream() throws KSMException;

}
