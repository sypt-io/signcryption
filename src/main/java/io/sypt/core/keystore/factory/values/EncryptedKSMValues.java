package io.sypt.core.keystore.factory.values;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.exception.SypterException;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.sypter.KeyStoreSypter;
import io.sypt.core.keystore.sypter.entity.KeyStoreSypterable;
import io.sypt.core.signer.exception.SignerException;

public class EncryptedKSMValues implements KSMValues {

	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	private String keyStore;
	private char[] password;
	
	public EncryptedKSMValues(
		String keyStore,
		KSMValuesData data,
		KSM masterKSM
	) throws KSMException {
		this.keyStore = keyStore;
		this.password = encryptPassword(data, masterKSM);
	}
	
	@Override
	public String getKeyStore() {
		return keyStore;
	}
	
	@Override
	public char[] getPassword() {
		return password;
	}
	
	private static char[] encryptPassword(KSMValuesData data, KSM masterKSM) throws KSMException {
		try {
			DefaultSypterGenerator gen = new DefaultSypterGenerator(masterKSM.getProvider());
			return new KeyStoreSypter(masterKSM).syptAndEncode(new KeyStoreSypterable(gen.generateId("SID-", 16), data)).toCharArray();
		} catch (SypterException | CrypterException | SignerException e) {
			throw new KSMException("Unable to encrypt KeyStore's password", e);
		}
	}

}
