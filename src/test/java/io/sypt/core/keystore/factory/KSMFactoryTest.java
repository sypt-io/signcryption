package io.sypt.core.keystore.factory;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.sypt.core.entity.Syptered;
import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.generator.SypterGenerator;
import io.sypt.core.keystore.DataKSM;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.KeyData;
import io.sypt.core.keystore.factory.KSMFactory.Usage;
import io.sypt.core.keystore.factory.entity.TestSypterable;
import io.sypt.core.keystore.factory.values.KSMValues;
import io.sypt.core.keystore.sypter.KeyStoreSypter;
import io.sypt.core.keystore.sypter.entity.KeyStoreSypterable;

class KSMFactoryTest {
	
	private final SypterGenerator gen = new DefaultSypterGenerator();
	
	private static final String ALIAS = "test";
	private static final String DOMAIN = "test.com";
	
	public KSMFactoryTest() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	void testRsa() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKeyStoreManager, Usage.SYPT));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNull();
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testRsaMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKeyStoreManager, Usage.MTLS));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedRsa() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKeyStoreManager, Usage.SYPT));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNull();
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedRsaMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKeyStoreManager, Usage.MTLS));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		org.assertj.core.api.Assertions.assertThat(certificate.getSubjectAlternativeNames())
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testEc() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKeyStoreManager, Usage.SYPT));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNull();
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testEcMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainKeyStoreManager(masterKeyStoreManager, Usage.MTLS));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedEc() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKeyStoreManager, Usage.SYPT));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNull();
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	@Test
	void testDecryptedEcMtls() throws Exception {
		final String id = gen.generateId("", 32);
		final String data = gen.generateId("", 32);

		KSM masterKeyStoreManager = new FileKSM("classpath:keystore/sypt-crypto-data-ec.p12",
			"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC");

		KSM keyStoreManager = Assertions.assertDoesNotThrow(() -> obtainDecryptedKeyStoreManager(masterKeyStoreManager, Usage.MTLS));
		Assertions.assertNotEquals(masterKeyStoreManager.getPrivateKey().getEncoded(), keyStoreManager.getPrivateKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getPublicKey().getEncoded(), keyStoreManager.getPublicKey().getEncoded());
		Assertions.assertNotEquals(masterKeyStoreManager.getCertificate().getEncoded(), keyStoreManager.getCertificate().getEncoded());
		
		Assertions.assertDoesNotThrow(() -> keyStoreManager.getCertificate().verify(masterKeyStoreManager.getPublicKey()));
		
		X509Certificate certificate = (X509Certificate) keyStoreManager.getCertificate();
		Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
		org.assertj.core.api.Assertions.assertThat(alternativeNames)
			.isNotEmpty()
			.containsExactly(List.of(2, DOMAIN));
		
		Syptered syptered = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).sypt(new TestSypterable(id, data)));
		TestSypterable unsypt = Assertions.assertDoesNotThrow(
				() -> new TestSypter(keyStoreManager).unsypt(syptered, TestSypterable.class));

		Assertions.assertEquals(id, unsypt.getId());
		Assertions.assertEquals(data, unsypt.getData());
	}

	private KSM obtainKeyStoreManager(
		KSM masterKeyStoreManager,
		Usage usage
	) throws Exception {
		KSMValues keyStoreValues = KSMFactory.builder()
				.keyStoreManager(masterKeyStoreManager)
				.alias(ALIAS)
				.domain(DOMAIN)
				.usage(usage)
				.build();

		KeyStoreSypterable passwordSypterable = new KeyStoreSypter(masterKeyStoreManager).decodeAndUnsypt(
				String.valueOf(keyStoreValues.getPassword()),
				KeyStoreSypterable.class);

		return new DataKSM(new ByteArrayInputStream(Base64.decode(keyStoreValues.getKeyStore())),
				passwordSypterable.getPassword(),
				new KeyData(ALIAS, passwordSypterable.getPassword()), "BC");
	}

	private KSM obtainDecryptedKeyStoreManager(
		KSM masterKeyStoreManager,
		Usage usage
	) throws Exception {
		KSMValues keyStoreValues = KSMFactory.builder()
				.keyStoreManager(masterKeyStoreManager)
				.alias(ALIAS)
				.domain(DOMAIN)
				.usage(usage)
				.encryptedPassword(false)
				.build();

		return new DataKSM(new ByteArrayInputStream(Base64.decode(keyStoreValues.getKeyStore())),
				keyStoreValues.getPassword(),
				new KeyData(ALIAS, keyStoreValues.getPassword()), "BC");
	}

}
