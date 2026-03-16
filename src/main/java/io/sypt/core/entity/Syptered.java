package io.sypt.core.entity;

public class Syptered {

	private String object;
	private String signature;

	public Syptered() {
		this("", "");
	}

	public Syptered(String object, String signature) {
		this.object = object;
		this.signature = signature;
	}

	public String getObject() {
		return object;
	}

	public String getSignature() {
		return signature;
	}

}
