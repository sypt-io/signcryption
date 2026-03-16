package io.sypt.core;

import java.util.function.Function;

import io.sypt.core.entity.Sypterable;
import io.sypt.core.entity.Syptered;
import io.sypt.core.exception.SypterException;

/**
 * Main interface exposing encryption / decryption methods
 * @param <T> An object extending {@link Sypterable} class
 * @author tazouxme
 */
public interface Sypter<T extends Sypterable> {
	
	/**
	 * Sign and Encrypt an entity
	 * @param T the object to sign and encrypt
	 * @return the object that contains the encrypted initial object and the signature
	 * @throws SypterException if something goes wrong with the encryption or signature generation
	 */
	public Syptered sypt(T entity) throws SypterException;
	
	/**
	 * Sign and Encrypt an entity
	 * @param T the object to sign and encrypt
	 * @return the object (JSON encoded in Base64) that contains the encrypted initial object and the signature
	 * @throws SypterException if something goes wrong with the encryption or signature generation
	 */
	public String syptAndEncode(T entity) throws SypterException;
	
	public default T unsypt(Syptered syptered, Class<T> clazz) throws SypterException {
		return unsypt(syptered, _ -> clazz);
	}
	
	public T unsypt(Syptered syptered, Function<String, Class<T>> determinator) throws SypterException;
	
	public default T decodeAndUnsypt(String value, Class<T> clazz) throws SypterException {
		return decodeAndUnsypt(value, _ -> clazz);
	}
	
	public T decodeAndUnsypt(String value, Function<String, Class<T>> determinator) throws SypterException;

}
