package io.sypt.core.keystore;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import io.sypt.core.keystore.exception.KSMException;

@ExtendWith(MockitoExtension.class)
class KSMTest {
	
	public KSMTest() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	void testGetKeystore() throws Exception {
		try (KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC")) {
			Assertions.assertDoesNotThrow(masterKeyStoreManager::getKeyStore);	
			Assertions.assertNotNull(masterKeyStoreManager.getKeyData());
		}
	}
	
	@ParameterizedTest
	@MethodSource("testGetNullDataKeystore")
	void testGetNullDataKeystore(InputStream is, char[] keystorePassword, char[] keyPassword) {
		KeyData keyData = new KeyData("sypt-crypto-data", keyPassword);
		Assertions.assertThrows(IllegalArgumentException.class, () -> new DataKSM(is, keystorePassword, keyData, "BC"));
	}
	
	@Test
	void testGetCertificate() throws Exception {
		try (KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC")) {
			Assertions.assertDoesNotThrow(masterKeyStoreManager::getCertificate);			
		}
	}
	
	@Test
	void testGetCertificateException() throws KSMException {
		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
				"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");
		KSM manager = Mockito.spy(masterKeyStoreManager);

		Mockito.doThrow(new KSMException("Forced failure"))
	        .when(manager)
	        .getKeyStore();

	    Assertions.assertThrows(KSMException.class, manager::getCertificate);
	}
	
	@Test
	void testGetPublicKey() throws Exception {
		try (KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC")) {
			Assertions.assertDoesNotThrow(masterKeyStoreManager::getPublicKey);			
		}
	}
	
	@Test
	void testGetPublicKeyNullException() throws KSMException {
		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
				"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");
		KSM manager = Mockito.spy(masterKeyStoreManager);

		Mockito.when(manager.getCertificate()).thenReturn(null);

	    Assertions.assertThrows(KSMException.class, manager::getPublicKey);
	}
	
	@Test
	void testGetPublicKeyException() throws KSMException {
		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
				"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");
		KSM manager = Mockito.spy(masterKeyStoreManager);

		Mockito.doThrow(new KSMException("Forced failure"))
	        .when(manager)
	        .getKeyStore();

	    Assertions.assertThrows(KSMException.class, manager::getPublicKey);
	}
	
	@Test
	void testGetPrivateKey() throws Exception {
		try (KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC")) {
			Assertions.assertDoesNotThrow(masterKeyStoreManager::getPrivateKey);			
		}
	}
	
	@Test
	void testGetPrivateKeyException() throws KSMException {
		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
				"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");
		KSM manager = Mockito.spy(masterKeyStoreManager);

		Mockito.doThrow(new KSMException("Forced failure"))
	        .when(manager)
	        .getKeyStore();

	    Assertions.assertThrows(KSMException.class, manager::getPrivateKey);
	}
	
	private static Stream<Arguments> testGetNullDataKeystore() {
		return Stream.of(
			Arguments.of(null, "keystorePassword".toCharArray(), "keyPassword".toCharArray()),
			Arguments.of(new ByteArrayInputStream(new byte[1]), null, "keyPassword".toCharArray()),
			Arguments.of(new ByteArrayInputStream(new byte[1]), "keystorePassword".toCharArray(), null)
		);
	}

}
