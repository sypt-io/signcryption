package io.sypt.core.crypter.factory;

import java.security.GeneralSecurityException;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.crypter.EcCrypter;
import io.sypt.core.crypter.RsaCrypter;
import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.KSMType;

public class CrypterFactory {
	
	private CrypterFactory() { }

	/**
	 * Get a Crypter depending on the KeyStore algorithm
	 * <ul>
	 * <li><code>EC (Elliptic Curve)</code> will return a <code>EcCrypter</code></li>
	 * <li><code>RSA</code> will return a <code>RsaCrypter</code></li>
	 * </ul>
	 * @param ksm
	 * @return the generated Crypter
	 * @throws CrypterException if the KSM is null or if the algorithm is not EC nor RSA
	 */
	public static final Crypter<byte[], AsymmetricSypterObject> getCrypter(KSM ksm) throws CrypterException {
		if (ksm == null) {
			throw new CrypterException("'keyStoreManager' cannot be null");
		}
		
		try {
			KSMType algorithm = ksm.getType();
			if (algorithm == null) {
				throw new CrypterException("Unable to retrieve KeyStoreManager type");
			}
			
			return switch (algorithm) {
				case EC_256, EC_384 -> new EcCrypter(ksm);
				case RSA_2048, RSA_4096 -> new RsaCrypter(ksm);
			};
		} catch (KSMException | GeneralSecurityException e) {
			throw new CrypterException("Unable to generate new Crypter", e);
		}
	}

}
