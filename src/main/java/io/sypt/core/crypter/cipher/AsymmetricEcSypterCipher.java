package io.sypt.core.crypter.cipher;

import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.keystore.KSM;

public final class AsymmetricEcSypterCipher extends AbstractAsymmetricSypterCipher {
	
	public AsymmetricEcSypterCipher(KSM ksm) throws GeneralSecurityException {
		super(ksm, Crypter.CIPHER_ASYMMETRIC_ALGO_EC);
	}
	
	public AsymmetricEcSypterCipher(KSM ksm, javax.crypto.Cipher cipher) {
		super(ksm, cipher);
	}
	
	@Override
	protected void initEncryptCipher(Cipher cipher, Key key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
	}
	
	@Override
	protected void initDecryptCipher(Cipher cipher, Key key) throws GeneralSecurityException {
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
	}

}
