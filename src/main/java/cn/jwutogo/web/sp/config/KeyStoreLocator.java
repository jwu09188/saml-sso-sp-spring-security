package cn.jwutogo.web.sp.config;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

/**
 * @author WuJiaGen
 * @data 22020-07-15 16:00
 */
public class KeyStoreLocator {

    private static CertificateFactory certificateFactory;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyStore createKeyStore(String pemPassPhrase) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, pemPassPhrase.toCharArray());
            return keyStore;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * privateKey必须采用DER未加密的PKCS＃8格式。
     */
    public static void addPrivateKey(KeyStore keyStore, String alias, String privateKey, String certificate, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
        String wrappedCert = wrapCert(certificate);
        Charset charset = StandardCharsets.UTF_8;
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes(charset));

        char[] passwordChars = password.toCharArray();
        Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes(charset)));
        ArrayList<Certificate> certs = new ArrayList<>();
        certs.add(cert);

        byte[] privateKeyBytes = IOUtils.toByteArray(new ByteArrayInputStream(decodedKey));

        KeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(ks);
        keyStore.setKeyEntry(alias, privKey, passwordChars, certs.toArray(new Certificate[certs.size()]));
    }

    private static String wrapCert(String certificate) {
        return "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----";
    }

}
