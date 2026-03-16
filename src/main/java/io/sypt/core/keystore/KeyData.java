package io.sypt.core.keystore;

import java.util.Objects;

public record KeyData(String alias, char[] pass) {
	
	@Override
	public final String toString() {
		StringBuilder b = new StringBuilder();
		b.append("alias = ").append(alias());
		b.append("; ");
		b.append("pass = ******");
		return b.toString();
	}
	
	@Override
	public final boolean equals(Object o) {
		if (o == null || !(o instanceof KeyData k)) {
			return false;
		}
		
		return k == this || k.alias != null && k.alias.equals(alias);
	}
	
	@Override
	public final int hashCode() {
		return Objects.hash(alias, pass);
	}

}
