package io.sypt.core.keystore.factory.values;

public class BasicKSMValues implements KSMValues {
	
	private String keyStore;
	private char[] password;
	
	public BasicKSMValues(String keyStore, char[] password) {
		this.keyStore = keyStore;
		this.password = password;
	}
	
	@Override
	public String getKeyStore() {
		return keyStore;
	}
	
	@Override
	public char[] getPassword() {
		return password;
	}

}
