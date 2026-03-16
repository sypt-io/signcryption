package io.sypt.core.keystore;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

public interface KSM extends AutoCloseable {
	
	public static final String AES = "AES";
	public static final String EC = "EC";
	public static final String RSA = "RSA";

	public static final String SHA256_WITH_ECDSA = "SHA256withECDSA";
	public static final String SHA384_WITH_ECDSA = "SHA384withECDSA";
	public static final String SHA256_WITH_RSA = "SHA256withRSA";

	public static final String KEY_STORE_TYPE = "pkcs12";
	
	/**
	 * Retrieve the loaded KeyStore
	 * @return KeyStore
	 * @throws KSMException
	 */
	public KeyStore getKeyStore() throws KSMException;
	
	/**
	 * Retrieve the {@link Certificate} from the KeyStore for the initialized alias
	 * @return Found {@link Certificate}
	 * @throws KSMException
	 */
	public Certificate getCertificate() throws KSMException;
	
	/**
	 * Retrieve the chain of {@link Certificate} from the KeyStore for the initialized alias
	 * @return Found chain of {@link Certificate}
	 * @throws KSMException
	 */
	public Certificate[] getCertificateChain() throws KSMException;

	/**
	 * Retrieve the {@link PublicKey} from the KeyStore for the initialized alias
	 * @return Found {@link PublicKey}
	 * @throws KSMException
	 */
	public PublicKey getPublicKey() throws KSMException;
	
	/**
	 * Retrieve the {@link PrivateKey} from the KeyStore for the initialized alias
	 * @return Found {@link PrivateKey}
	 * @throws KSMException
	 */
	public PrivateKey getPrivateKey() throws KSMException;
	
	/**
	 * Retrieve the {@link KeyData} from the KeyStore for the initialized alias
	 * @return Alias and its associated password
	 */
	public KeyData getKeyData();
	
	/**
	 * Retrieve the Provider used to instantiate the KeyStore
	 * @return The Provider
	 */
	public String getProvider();
	
	/**
	 * Retrieve the {@link KSMType} based on the Certificate type (RSA / EC)
	 * @return Related {@link KSMType}
	 * @throws KSMException
	 */
	default KSMType getType() throws KSMException {
		return KSMType.fromGeneratorType(getPublicKey().getAlgorithm());
	}

}
