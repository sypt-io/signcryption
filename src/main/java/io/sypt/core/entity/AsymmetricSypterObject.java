package io.sypt.core.entity;

public class AsymmetricSypterObject {

	private String encryptedData;
	private String encryptedSecretKey;
	private String encryptedIv;

	public AsymmetricSypterObject() {
		this("", "", "");
	}

	public AsymmetricSypterObject(String encryptedData, String encryptedSecretKey, String encryptedIv) {
		this.encryptedData = encryptedData;
		this.encryptedSecretKey = encryptedSecretKey;
		this.encryptedIv = encryptedIv;
	}

	public String getEncryptedData() {
		return encryptedData;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	public String getEncryptedSecretKey() {
		return encryptedSecretKey;
	}

	public void setEncryptedSecretKey(String encryptedSecretKey) {
		this.encryptedSecretKey = encryptedSecretKey;
	}

	public String getEncryptedIv() {
		return encryptedIv;
	}

	public void setEncryptedIv(String encryptedIv) {
		this.encryptedIv = encryptedIv;
	}

}
