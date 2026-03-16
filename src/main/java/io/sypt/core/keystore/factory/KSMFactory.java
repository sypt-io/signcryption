package io.sypt.core.keystore.factory;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.sypt.core.generator.DefaultSypterGenerator;
import io.sypt.core.generator.SypterGenerator;
import io.sypt.core.keystore.KSM;
import io.sypt.core.keystore.exception.KSMException;
import io.sypt.core.keystore.factory.values.BasicKSMValues;
import io.sypt.core.keystore.factory.values.EncryptedKSMValues;
import io.sypt.core.keystore.factory.values.KSMValues;
import io.sypt.core.keystore.factory.values.KSMValuesData;

/**
 * KeyStore generator Factory
 * @author tazouxme
 */
public class KSMFactory {
	
	protected final Logger log = LoggerFactory.getLogger(getClass());
	
	private final SecureRandom secureRandom = new SecureRandom();
	
	public enum Usage {
		/**
		 * Gives the ability to generate digital signature and encipher keys
		 */
		SYPT,
		
		/**
		 * Gives the ability to generate digital signature <b>as a client</b> in a mTLS context
		 */
		MTLS;
	}
	
	public static class Builder {
		
		private KSM ksm;
		private SypterGenerator generator;
		private String alias;
		private String domain;
		private Usage usage;
		private int validity = 730;
		private boolean encryptedPassword = true;
		
		/**
		 * The master KSM used to generate and secure the subsequent generated KSM
		 * @param ksm - cannot be null
		 * @return
		 */
		public Builder keyStoreManager(KSM ksm) {
			this.ksm = ksm;
			return this;
		}
		
		/**
		 * The alias used for the newly generated KSM
		 * @param alias - cannot be empty
		 * @return
		 */
		public Builder alias(String alias) {
			this.alias = alias;
			return this;
		}

		/**
		 * The domain used for the newly generated KSM
		 * @param domain - cannot be empty
		 * @return
		 */
		public Builder domain(String domain) {
			this.domain = domain;
			return this;
		}
		
		/**
		 * {@link Usage} for the generated Certificate
		 * @param usage - cannot be empty
		 * @return
		 */
		public Builder usage(Usage usage) {
			this.usage = usage;
			return this;
		}

		/**
		 * The validity in days of the newly generated KSM
		 * @param validity - default 730
		 * @return
		 */
		public Builder validity(int validity) {
			this.validity = validity;
			return this;
		}

		/**
		 * Whether the generated password of the KSM must be encrypted or not
		 * @param encryptedPassword - default true 
		 * @return
		 */
		public Builder encryptedPassword(boolean encryptedPassword) {
			this.encryptedPassword = encryptedPassword;
			return this;
		}

		/**
		 * The generator used for KSM data generation
		 * @param generator - can be null
		 * @return
		 */
		public Builder generator(SypterGenerator generator) {
			this.generator = generator;
			return this;
		}
		
		public KSMValues build() throws KSMException {
			Objects.requireNonNull(ksm, "KSMFactory parameter 'keyStoreManager' is not set");
			Objects.requireNonNull(alias, "KSMFactory parameter 'alias' is not set");
			Objects.requireNonNull(domain, "KSMFactory parameter 'domain' is not set");
			Objects.requireNonNull(usage, "KSMFactory parameter 'usage' is not set");
			
			if (this.generator == null) {
	            this.generator = new DefaultSypterGenerator(ksm.getProvider());
	        }
			
			KSMFactory factory = new KSMFactory();
			KSMData data = new KSMData(ksm.getType(), alias, domain, validity);
			
			return factory.generateKeyStore(data, ksm, generator, usage, encryptedPassword);
		}
		
	}
	
	private KSMFactory() { }
	
	public static final Builder builder() {
		return new Builder();
	}

	/**
	 * Factory method to generate a new KeyStore
	 * @param data Includes the Type (EC or RSA), Alias, Domain and validity of the KeyStore
	 * @param masterKSM Used to encrypt and sign the password of the KeyStore
	 * @param encryptPassword Whether the password should be encrypted or clear
	 * @return The KeyStore and its password
	 * @throws KSMException
	 */
	private KSMValues generateKeyStore(
		KSMData data,
		KSM masterKSM,
		SypterGenerator generator,
		Usage usage,
		boolean encryptPassword
	) throws KSMException {
		if (masterKSM == null) {
			throw new KSMException("'masterKSM' cannot be null");
		}
		
		try {
			log.trace("Generating new password");
			final char[] keyStorePassword = generator.generateId("SPASS-", 32).toCharArray();
			
			log.trace("Generating new Key pair");
			String provider = masterKSM.getProvider();
			KeyPairGenerator keyPairGenerator = StringUtils.isBlank(provider)
					? KeyPairGenerator.getInstance(data.type().keyPairGeneratorType())
					: KeyPairGenerator.getInstance(data.type().keyPairGeneratorType(), provider);
			keyPairGenerator.initialize(data.type().params());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			log.trace("Generating new KeyStore");
			KeyStore ks = StringUtils.isBlank(provider)
					? KeyStore.getInstance(KSM.KEY_STORE_TYPE)
					: KeyStore.getInstance(KSM.KEY_STORE_TYPE, provider);
			ks.load(null, null);
			
			List<Certificate> certificateChain = new ArrayList<>(4);
			certificateChain.add(generateCertificate(data, keyPair, masterKSM, usage)); 
			
			List<Certificate> masterCertificateChain = Arrays.asList(masterKSM.getCertificateChain());
			if (masterCertificateChain != null) {
				certificateChain.addAll(masterCertificateChain);
			}

			ks.setKeyEntry(
				data.alias(), 
				keyPair.getPrivate(),
				keyStorePassword,
				certificateChain.toArray(new Certificate[0])
			);

			try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
				log.trace("Storing new KeyStore");
				ks.store(os, keyStorePassword);
				
				if (encryptPassword) {
					return new EncryptedKSMValues(
						new String(Base64.encode(os.toByteArray())),
						new KSMValuesData(data.alias(), data.domain(), keyStorePassword),
						masterKSM);
				}
				
				return new BasicKSMValues(
					new String(Base64.encode(os.toByteArray())),
					keyStorePassword
				);
			}
		} catch (Exception e) {
			throw new KSMException("Unable to generate a new key store", e);
		}
	}

	private Certificate generateCertificate(
		KSMData data,
		KeyPair keyPair,
		KSM masterKSM,
		Usage usage
	) throws KSMException {
		Provider provider = Security.getProvider(masterKSM.getProvider());
		
		String cn = data.domain();
		Calendar calendar = Calendar.getInstance();

        ContentSigner csrContentSigner;
        try {
        	csrContentSigner = new JcaContentSignerBuilder(data.type().contentSignerType())
        		.setProvider(provider)
        		.build(masterKSM.getPrivateKey());
        } catch (OperatorCreationException e) {
        	throw new KSMException("Unable to build the content signer with master private key", e);
        }

		log.trace("Signing the new Key pair with the root certificate Private Key");
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + cn), keyPair.getPublic())
       		.build(csrContentSigner);
        
        X500Name subject;
        try {
        	 subject = new JcaX509CertificateHolder((X509Certificate) masterKSM.getCertificate()).getSubject();
        } catch (CertificateEncodingException e) {
        	throw new KSMException("Unable to extract the master certificate information", e);
        }

        // Here serial number is randomly generated. In general, CAs use a sequence to generate Serial number and avoid collisions
        log.trace("Using the signed Key pair and CSR to generate an issued Certificate");
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(
    		subject,
    		new BigInteger(Long.toString(secureRandom.nextLong())),
    		generateStartDate(calendar),
    		generateEndDate(calendar, data.validity()),
    		csr.getSubject(),
    		csr.getSubjectPublicKeyInfo()
        );

        // Add Extensions
        try {
        	// Use BasicConstraints to say that this certificate is not a CA
			issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

	        // Add intended key usage extension if needed
			if (usage == Usage.MTLS) {
				issuedCertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
				issuedCertBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

		        // Add DNS name to certificate is to used for SSL
		        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
		            new GeneralName(GeneralName.dNSName, cn)
		        }));
			}
			
			if (usage == Usage.SYPT) {
				issuedCertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement));
			}

	        // Add Issuer cert identifier as Extension
	        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();
	        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier((X509Certificate) masterKSM.getCertificate()));
	        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

	        log.trace("Generating new Certificate");
	        X509Certificate issuedCert  = new JcaX509CertificateConverter()
	    		.setProvider(provider)
	    		.getCertificate(issuedCertBuilder.build(csrContentSigner));

	        log.trace("Verifying the issued certificate signature against the root (issuer) certificate");
	        issuedCert.verify(masterKSM.getPublicKey(), provider);
	        
	        return issuedCert;
		} catch (Exception e) {
        	throw new KSMException("Unable to generate a new Certificate", e);
		}
	}
	
	private static Date generateStartDate(Calendar calendar) {
		calendar.add(Calendar.DATE, -1);
        return calendar.getTime();
	}
	
	private static Date generateEndDate(Calendar calendar, int validity) {
		calendar.add(Calendar.DATE, validity);
        return calendar.getTime();
	}

}
