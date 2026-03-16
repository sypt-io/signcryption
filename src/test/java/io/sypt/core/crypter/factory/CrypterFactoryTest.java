package io.sypt.core.crypter.factory;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;

class CrypterFactoryTest {
	
	@Test
	void getCrypterNoKeyStoreManager() {
		Assertions.assertThrows(CrypterException.class, () -> CrypterFactory.getCrypter(null));
	}
	
	@Test
	void getCrypterNoPublicKey() throws Exception {
		KSM keyStoreManager = Mockito.mock(KSM.class);
		Mockito.doThrow(new KSMException("")).when(keyStoreManager).getPublicKey();
		
		Assertions.assertThrows(CrypterException.class, () -> CrypterFactory.getCrypter(keyStoreManager));
	}

}
