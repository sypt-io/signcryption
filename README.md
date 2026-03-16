# sypt.io - signcryption
A small library that helps to cipher a secret and sign it.

## Generate a KeyStore
```java
// Build a new KeyStore
KSMValues ksmValues = KSMFactory.builder()
	.keyStoreManager(masterKsm)
	.alias(alias)
	.domain(domain)
	.usage(Usage.SYPT)
	.encryptedPassword(false)
	.build();
    
// Access the KeyStore
ksmValues.getKeyStore();

// Access the password (encrypted here using the master KSM)
ksmValues.getPassword();
```

## Use the KeyStore to encrypt / sign your data

```java
// Create your KSM using BouncyCastle
try (KSM ksm = new DataKSM(
	new ByteArrayInputStream(Base64.decode(ksmValues.getKeyStore())),
	ksmValues.getPassword(),
	new KeyData(alias, ksmValues.getPassword()), "BC")
) {
	// Create your Sypter
	Sypter<YourSypterable> sypter = new YourSypter(ksm);
	// Sypt your data
	String encryptedData = sypter.syptAndEncode(new YourSypterable(yourData));
}
```

### Data representation
You will receive a Base64 encoded JSON

```
eyJvYmplY3QiOiJleUpsYm1OeWVYQjBaV1JFWVhSaElqb2lhR0ZPU2pWQ1Iybb...
```

This represents a JSON with following values

```json
{
	"object": "...",
	"signature": "..."
}
```

The values 'object' is itself a Base64 encoded JSON containing the encrypted values

```json
{
	"encryptedData": "...",
	"encryptedIv": "...",
	"encryptedSecretKey" : "..." // this is the AES key encrypted by the KeyStore's PrivateKey
}
```

## Use the KeyStore to decrypt / verify your data

```java
// Create your KSM using BouncyCastle
try (KSM ksm = new DataKSM(
	new ByteArrayInputStream(Base64.decode(ksmValues.getKeyStore())),
	ksmValues.getPassword(),
	new KeyData(alias, ksmValues.getPassword()), "BC")
) {
	// Create your Sypter
	Sypter<YourSypterable> sypter = new YourSypter(ksm);
	// Unsypt your data
	YourSypterable yourData = sypter.decodeAndUnsypt(encryptedData YourSypterable.class);
}
```