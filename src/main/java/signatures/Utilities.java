package signatures;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Utilities {

    // Private constructor to prevent instantiation.
    private Utilities() {
        throw new UnsupportedOperationException();
    }

    public static String getFileBodyAt(String envVar) {
        try {
            String pathToFile = System.getenv(envVar);
            if (pathToFile == null) {
                // If the env var is unset, it presents as null.
                throw new RuntimeException(envVar + " environment variable must be set");
            }
            Stream<String> streamer = Files.lines(Paths.get(pathToFile));
            String body = streamer.collect(Collectors.joining("\n"));
            streamer.close();
            return body;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String getStringToSign(String role, String signingTimeStr, String cfInstanceCert) {
        return signingTimeStr + cfInstanceCert + role;
    }

    public static String generateSignature(String privateKeyPem, byte[] data) {
        try (PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();

            KeyFactory factory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pemKeyPair.getPublicKeyInfo().getEncoded());
            PublicKey publicKey = factory.generatePublic(publicKeySpec);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemKeyPair.getPrivateKeyInfo().getEncoded());
            PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
            KeyPair kp = new KeyPair(publicKey, privateKey);
            RSAPrivateKeySpec privKeySpec = factory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

            PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), 222);
            signer.init(true, new RSAKeyParameters(true, privKeySpec.getModulus(), privKeySpec.getPrivateExponent()));
            signer.update(data, 0, data.length);
            byte[] signature = signer.generateSignature();

            return java.util.Base64.getUrlEncoder().encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
