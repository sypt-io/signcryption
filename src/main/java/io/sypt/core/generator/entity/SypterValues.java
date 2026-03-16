package io.sypt.core.generator.entity;

import java.security.Key;
import java.util.Arrays;
import java.util.Objects;

import org.bouncycastle.util.encoders.Base64;

public record SypterValues(Key key, byte[] iv) {

	public String encodedIv() {
		return new String(Base64.encode(iv));
	}
	
	@Override
	public final boolean equals(Object obj) {
		if (this == obj) return true;
			
		if (obj instanceof SypterValues(Key key, byte[] iv)) {
			return key.equals(key()) && Arrays.equals(iv, iv());
		}
		
		return false;
	}
	
	@Override
	public final int hashCode() {
		return Objects.hash(key(), iv());
	}
	
	@Override
	public final String toString() {
		StringBuilder b = new StringBuilder();
		b.append("Format: ");
		b.append(key.getFormat());
		b.append(", Algorithm: ");
		b.append(key.getAlgorithm());
		
		return b.toString();
	}

}
