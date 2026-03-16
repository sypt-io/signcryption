package io.sypt.core.signer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.signer.exception.SignerException;

class SignerTest {
	
	@Test
	void signExceptionNoKeyStoreManager() {
		Signer signer = new EcSigner(null);
		Assertions.assertThrows(SignerException.class, () -> signer.sign(new byte[0]));
	}
	
	@Test
	void signExceptionNoPrivateKey() throws Exception {
		KSM keyStoreManager = Mockito.mock(KSM.class);
		Mockito.doThrow(new KSMException("")).when(keyStoreManager).getPrivateKey();

		Signer signer = Mockito.spy(new EcSigner(keyStoreManager));
		Assertions.assertThrows(SignerException.class, () -> signer.sign(new byte[0]));
	}
	
	@Test
	void signExceptionInvalidPrivateKey() {
		Signer signer = new EcSigner(null);
		Assertions.assertThrows(SignerException.class, () -> signer.sign(new byte[0], null));
	}
	
	@Test
	void verifyExceptionNoKeyStoreManager() {
		Signer signer = new EcSigner(null);
		Assertions.assertThrows(SignerException.class, () -> signer.verify(new byte[0], new byte[0]));
	}
	
	@Test
	void verifyExceptionNoPublicKey() throws Exception {
		KSM keyStoreManager = Mockito.mock(KSM.class);
		Mockito.doThrow(new KSMException("")).when(keyStoreManager).getPublicKey();

		Signer signer = Mockito.spy(new EcSigner(keyStoreManager));
		Assertions.assertThrows(SignerException.class, () -> signer.verify(new byte[0], new byte[0]));
	}
	
	@Test
	void verifyExceptionInvalidPublicKey() {
		Signer signer = new EcSigner(null);
		Assertions.assertThrows(SignerException.class, () -> signer.verify(new byte[0], new byte[0], null));
	}

}
