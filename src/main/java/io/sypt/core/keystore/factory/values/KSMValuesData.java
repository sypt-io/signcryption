package io.sypt.core.keystore.factory.values;

import java.io.Serializable;
import java.util.Objects;

public record KSMValuesData(
	String alias,
	String domain,
	char[] password
) implements Serializable {
	
	@Override
	public final String toString() {
		StringBuilder b = new StringBuilder();
		b.append("alias = ");
		b.append(alias);
		b.append(", domain = ");
		b.append(domain);
		return b.toString();
	}
	
	@Override
	public final boolean equals(Object o) {
		if (o == null ||!(o instanceof KSMValuesData v)) {
			return false;
		}
		
		if (v.alias == null || v.domain == null) {
			return false;
		}
		
		return v.alias.equals(alias) && v.domain.equals(domain);
	}
	
	@Override
	public final int hashCode() {
		return Objects.hash(alias, domain);
	}

}
