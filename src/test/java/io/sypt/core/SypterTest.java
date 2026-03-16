package io.sypt.core;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.entity.Sypterable;
import io.sypt.core.entity.Syptered;
import io.sypt.core.exception.SypterException;
import io.sypt.core.keystore.FileKSM;
import io.sypt.core.keystore.KeyData;
import io.sypt.core.signer.exception.SignerException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
class SypterTest {
	
	public SypterTest() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	void testSypt() throws CrypterException, SignerException {
		AbstractSypterTest sypter = new AbstractSypterTest();
		Assertions.assertDoesNotThrow(() -> sypter.sypt(new SypterableTest()));
	}
	
	@Test
	void testSyptException() throws CrypterException, SignerException {
		AbstractSypterTest sypter = new AbstractSypterTest();
		Assertions.assertThrows(SypterException.class, () -> sypter.sypt(null));
	}
	
	@Test
	void testSyptAndEncode() throws Exception {
		AbstractSypterTest sypter = new AbstractSypterTest();
		Assertions.assertDoesNotThrow(() -> sypter.syptAndEncode(new SypterableTest()));
	}
	
	@Test
	void testSyptAndEncodeException() throws Exception {
		ObjectMapper failingMapper = Mockito.mock(ObjectMapper.class);
		Mockito.doThrow(new JacksonException("Serialization failed") {}).when(failingMapper).writeValueAsBytes(ArgumentMatchers.any());

		AbstractSypterTest sypter = Mockito.spy(new AbstractSypterTest(failingMapper));
		Mockito.doReturn(new Syptered()).when(sypter).sypt(ArgumentMatchers.any());
	    
		Assertions.assertThrows(SypterException.class, () -> sypter.syptAndEncode(new SypterableTest()));
	}
	
	@Test
	void testUnsypt() throws Exception {
		AbstractSypterTest sypter = new AbstractSypterTest();
		Syptered syptered = Assertions.assertDoesNotThrow(() -> sypter.sypt(new SypterableTest()));
		Assertions.assertDoesNotThrow(() -> sypter.unsypt(syptered, SypterableTest.class));
	}
	
	@Test
	void testUniversalUnsypt() throws Exception {
		AbstractSypterTest sypter = new AbstractSypterTest();
		AbstractUniversalSypterTest universalSypter = new AbstractUniversalSypterTest();
		Syptered syptered = Assertions.assertDoesNotThrow(() -> sypter.sypt(new SypterableTest()));
		Assertions.assertDoesNotThrow(() -> universalSypter.unsypt(syptered, SypterableTest.class));
	}
	
	@Test
	void testUnsyptException() throws CrypterException, SignerException {
		AbstractSypterTest sypter = new AbstractSypterTest();
		Assertions.assertThrows(SypterException.class, () -> sypter.unsypt(null, SypterableTest.class));
	}
	
	@Test
	void testDecodeAndUnsypt() throws Exception {
		AbstractSypterTest sypter = new AbstractSypterTest();
		String syptered = Assertions.assertDoesNotThrow(() -> sypter.syptAndEncode(new SypterableTest()));
		Assertions.assertDoesNotThrow(() -> sypter.decodeAndUnsypt(syptered, SypterableTest.class));
	}
	
	@SuppressWarnings("unchecked")
	@Test
	void testDecodeAndUnsyptException() throws Exception {
		ObjectMapper failingMapper = Mockito.mock(ObjectMapper.class);
		Mockito.doThrow(new JacksonException("") {}).when(failingMapper).readValue(ArgumentMatchers.any(byte[].class), ArgumentMatchers.any(Class.class));

		AbstractSypterTest sypter = Mockito.spy(new AbstractSypterTest(failingMapper));
		String data = new String(Base64.encode("".getBytes()));
		Assertions.assertThrows(SypterException.class, () -> sypter.decodeAndUnsypt(data, SypterableTest.class));
	}
	
	private class AbstractSypterTest extends AbstractSypter<SypterableTest> {

		protected AbstractSypterTest() throws CrypterException, SignerException {
			super(new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
					"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC"));
		}

		protected AbstractSypterTest(ObjectMapper mapper) throws CrypterException, SignerException {
			super(new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
					"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray()), "BC"), mapper);
		}
		
		@Override
		protected boolean isEntityValid(SypterableTest obj) {
			return obj != null;
		}
		
	}
	
	private class AbstractUniversalSypterTest extends AbstractSypter<SypterableTest> {

		protected AbstractUniversalSypterTest() throws CrypterException, SignerException {
			super(new FileKSM("classpath:keystore/sypt-crypto-data-rsa.p12",
					"sypt-crypto-data-pass".toCharArray(), new KeyData("sypt-crypto-data", "sypt-crypto-data-pass".toCharArray())));
		}
		
		@Override
		protected boolean isEntityValid(SypterableTest obj) {
			return obj != null;
		}
		
	}
	
	private static class SypterableTest implements Sypterable {
		
		private String id = "ID";

		@Override
		public String getId() {
			return id;
		}
		
		@SuppressWarnings("unused")
		public void setId(String id) {
			this.id = id;
		}
		
	}

}
