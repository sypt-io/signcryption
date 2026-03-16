package io.sypt.core.keystore;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KeyDataTest {
	
	@Test
	void newInstance() {
		KeyData data = new KeyData("alias", "pass".toCharArray());
		Assertions.assertEquals("alias = alias; pass = ******", data.toString());
	}
	
	@Test
	void isEqual() {
		KeyData d1 = new KeyData("alias", "pass".toCharArray());
		KeyData d2 = new KeyData("alias", "pass".toCharArray());
		Assertions.assertEquals(d1, d2);
		
		KeyData d3 = new KeyData("alias", "pass".toCharArray());
		KeyData d4 = new KeyData("alias", "pas".toCharArray());
		Assertions.assertEquals(d3, d4);
	}
	
	@Test
	void isNotEqual() {
		KeyData d1 = new KeyData("alias", "pass".toCharArray());
		KeyData d2 = new KeyData("alia", "pass".toCharArray());
		Assertions.assertNotEquals(d1, d2);
		
		d1 = new KeyData("alias", "pass".toCharArray());
		d2 = new KeyData(null, "pass".toCharArray());
		Assertions.assertNotEquals(d1, d2);
		
		KeyData d3 = new KeyData("alias", "pass".toCharArray());
		KeyData d4 = null;
		Assertions.assertNotEquals(d3, d4);
	}

}
