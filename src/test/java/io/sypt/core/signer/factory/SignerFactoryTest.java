package io.sypt.core.signer.factory;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.signer.exception.SignerException;

class SignerFactoryTest {
	
	@Test
	void getSignerNoKeyStoreManager() {
		Assertions.assertThrows(SignerException.class, () -> SignerFactory.getSigner(null));
	}
	
	@Test
	void getSignerNoPublicKey() throws Exception {
		KSM keyStoreManager = Mockito.mock(KSM.class);
		Mockito.doThrow(new KSMException("")).when(keyStoreManager).getPublicKey();
		
		Assertions.assertThrows(SignerException.class, () -> SignerFactory.getSigner(keyStoreManager));
	}

}
