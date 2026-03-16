package io.sypt.core;

import java.util.function.Function;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.crypter.Crypter;
import io.sypt.core.crypter.exception.CrypterException;
import io.sypt.core.crypter.factory.CrypterFactory;
import io.sypt.core.entity.AsymmetricSypterObject;
import io.sypt.core.entity.Sypterable;
import io.sypt.core.entity.Syptered;
import io.sypt.core.exception.SypterException;
import io.sypt.core.keystore.KSM;
import io.sypt.core.signer.Signer;
import io.sypt.core.signer.exception.SignerException;
import io.sypt.core.signer.factory.SignerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

public abstract class AbstractSypter<T extends Sypterable> implements Sypter<T> {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	private final ObjectMapper mapper;
	
	private final Crypter<byte[], AsymmetricSypterObject> crypter;
	private final Signer signer;
	
	protected AbstractSypter(
		KSM ksm
	) throws CrypterException, SignerException {
		this(ksm, new ObjectMapper());
	}
	
	protected AbstractSypter(
		KSM ksm,
		ObjectMapper mapper
	) throws CrypterException, SignerException {
		this(CrypterFactory.getCrypter(ksm), SignerFactory.getSigner(ksm), mapper);
	}
	
	protected AbstractSypter(
		Crypter<byte[], AsymmetricSypterObject> crypter,
		Signer signer,
		ObjectMapper mapper
	) {
		this.crypter = crypter;
		this.signer = signer;
		this.mapper = mapper;
	}

	@Override
	public Syptered sypt(T entity) throws SypterException {
		log.debug("Sypt data");
		if (!isEntityValid(entity)) {
			log.warn("Sypt data are not valid");
			throw new SypterException("Entity cannot be validated");
		}
		
		String object = new String(Base64.encode(encrypt(entity).getBytes()));
		return new Syptered(object, sign(entity, object));
	}
	
	@Override
	public String syptAndEncode(T entity) throws SypterException {
		try {
			return new String(Base64.encode(mapper.writeValueAsBytes(sypt(entity))));
		} catch (JacksonException e) {
			throw new SypterException("Unable to sypt and encode the entity", e);
		}
	}

	@Override
	public T unsypt(Syptered syptered, Function<String, Class<T>> determinator) throws SypterException {
		log.debug("Unsypt data");
		if (syptered == null || StringUtils.isBlank(syptered.getObject()) || StringUtils.isBlank(syptered.getSignature())) {
			log.warn("Unsypt data are not valid");
			throw new SypterException("Syptered data cannot be empty");
		}
		
		T entity = decrypt(new String(Base64.decode(syptered.getObject())), determinator);
		if (!verify(entity, syptered.getObject(), syptered.getSignature())) {
			log.warn("Unsypt signature cannot be verifier");
			throw new SypterException("Cannot verify the digital signature");
		}

		return entity;
	}
	
	@Override
	public T decodeAndUnsypt(String value, Function<String, Class<T>> determinator) throws SypterException {
		try {
			return unsypt(mapper.readValue(Base64.decode(value), Syptered.class), determinator);
		} catch (JacksonException e) {
			log.warn("Unable to decode and unsypt the value");
			throw new SypterException("Unable to decode and unsypt the value", e);
		}
	}
	
	private String encrypt(T entity) throws SypterException {
		log.debug("Encrypt data");
		String json = toJSON(entity);
		
		try {
			AsymmetricSypterObject encrypt = crypter.encrypt(json.getBytes());
			return toJSON(encrypt);
		} catch (CrypterException e) {
			log.warn("Cannot encrypt data");
			throw new SypterException("Cannot encrypt data", e);
		}
	}
	
	private T decrypt(String json, Function<String, Class<T>> determinator) throws SypterException {
		log.debug("Decrypt data");
		AsymmetricSypterObject object = fromJSON(json, AsymmetricSypterObject.class);
		
		try {
			String o = new String(crypter.decrypt(object));
			return fromJSON(o, determinator.apply(o));
		} catch (CrypterException e) {
			log.warn("Cannot decrypt data");
			throw new SypterException("Cannot decrypt data", e);
		}
	}
	
	private String sign(T obj, String json) throws SypterException {
		log.debug("Sign data");
		String toSign = getId(obj) + Signer.ID_SEPARATOR + json;
		
		try {
			return signer.sign(toSign.getBytes());
		} catch (SignerException e) {
			log.warn("Cannot sign data");
			throw new SypterException("Cannot sign data", e);
		}
	}
	
	private boolean verify(T obj, String json, String signature) throws SypterException {
		log.debug("Verify data");
		String toVerify = getId(obj) + Signer.ID_SEPARATOR + json;
		
		try {
			return signer.verify(toVerify.getBytes(), signature.getBytes());
		} catch (SignerException e) {
			log.warn("Cannot verify signature");
			throw new SypterException("Cannot verify signature", e);
		}
	}

	private String toJSON(Object input) throws SypterException {
		if (input == null) {
			throw new SypterException("Cannot convert nothing to JSON object");
		}
		
		try {
			return mapper.writeValueAsString(input);
		} catch (JacksonException e) {
			throw new SypterException("Cannot convert to JSON object", e);
		}
	}

	private <O> O fromJSON(String json, Class<O> c) throws SypterException {
		if (StringUtils.isBlank(json)) {
			throw new SypterException("Cannot convert empty JSON object");
		}
		
		if (c == null) {
			throw new SypterException("Target class cannot be null");
		}
		
		try {
			return mapper.readValue(json, c);
		} catch (JacksonException e) {
			throw new SypterException("Cannot convert from JSON object", e);
		}
	}
	
	protected abstract boolean isEntityValid(T obj);
	
	private String getId(T obj) {
		return obj.getId();
	}

}
