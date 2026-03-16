package io.sypt.core.keystore.factory;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.KSMProperties;

public enum KSMType {
	
	EC_256		(KSM.EC, KSM.SHA256_WITH_ECDSA, new ECNamedCurveGenParameterSpec("P-256")),
	EC_384		(KSM.EC, KSM.SHA384_WITH_ECDSA, new ECNamedCurveGenParameterSpec("P-384")),
	RSA_2048	(KSM.RSA, KSM.SHA256_WITH_RSA, new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(0x10001))),
	RSA_4096	(KSM.RSA, KSM.SHA256_WITH_RSA, new RSAKeyGenParameterSpec(4096, BigInteger.valueOf(0x10001)));
	
	private final String keyPairGenerator;
	private final String contentSigner;
	private final AlgorithmParameterSpec params;
	
	private KSMType(String keyPairGenerator, String contentSigner, AlgorithmParameterSpec params) {
		this.keyPairGenerator = keyPairGenerator;
		this.contentSigner = contentSigner;
		this.params = params;
	}
	
	public String keyPairGeneratorType() {
		return keyPairGenerator;
	}
	
	public String contentSignerType() {
		return contentSigner;
	}
	
	public AlgorithmParameterSpec params() {
		return params;
	}
	
	public static KSMType fromGeneratorType(String type) {
		return switch (type) {
			case KSM.EC -> KSMProperties.getEcType();
			case KSM.RSA -> KSMProperties.getRsaType();
			default -> null;
		};
	}

}
