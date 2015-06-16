package org.springframework.security.ldap.server;

import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.extended.StartTlsHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public class ApacheDsSSLContainer extends ApacheDSContainer {
    private int port = 53389;
    private int sslPort = 53636;

    private String keystoreFile;
    private File workingDir;
    private boolean useStartTLS = false;

    public boolean isUseStartTLS() {
        return useStartTLS;
    }

    public void setUseStartTLS(boolean useStartTLS) {
        this.useStartTLS = useStartTLS;
    }

    public String getKeystoreFile() {
        return keystoreFile;
    }

    public void setKeystoreFile(String keystoreFile) {
        this.keystoreFile = keystoreFile;
    }

    public ApacheDsSSLContainer(String root, String ldifs) throws Exception {
        super(root, ldifs);
    }

    @Override
    public void setWorkingDirectory(File workingDir) {
        super.setWorkingDirectory(workingDir);
        this.workingDir = workingDir;
        if (!workingDir.mkdirs()) {
            throw new RuntimeException("Unable to create directory:"+workingDir);
        }
    }

    public File getWorkingDirectory() {
        return workingDir;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        server = new LdapServer();
        server.setDirectoryService(service);
        TcpTransport sslTransport = new TcpTransport(sslPort);
        if (isUseStartTLS()) {
            server.addExtendedOperationHandler(new StartTlsHandler());
        } else {
            sslTransport.setEnableSSL(true);
        }
        TcpTransport tcpTransport = new TcpTransport(port);
        server.setTransports(sslTransport, tcpTransport);
        assert server.isEnableLdaps(sslTransport);
        assert !server.isEnableLdaps(tcpTransport);
        server.setCertificatePassword("password");
        server.setKeystoreFile(getKeystore(getWorkingDirectory()).getAbsolutePath());
        start();
    }

    public void setSslPort(int sslPort) {
        this.sslPort = sslPort;
    }

    @Override
    public void setPort(int port) {
        super.setPort(port);
        this.port = port;
    }


    private static final int keysize = 1024;
    private static final String commonName = "localhost";
    private static final String organizationalUnit = "UAA";
    private static final String organization = "Pivotal Software";
    private static final String city = "San Francisco";
    private static final String state = "CA";
    private static final String country = "UA";
    private static final long validity = 1096; // 3 years
    private static final String alias = "uaa-ldap";
    private static final char[] keyPass = "password".toCharArray();

    //mimic what the keytool does
    public File getKeystore(File directory) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(keysize);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        X500Principal x500Principal = new X500Principal(
            String.format(
                "CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s",
                commonName, organizationalUnit, organization, city, state, country));

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());

        X509CertificateHolder certHolder = new JcaX509v3CertificateBuilder(
            x500Principal,
            BigInteger.ONE,
            new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
            new Date(System.currentTimeMillis() + 365 * 60 * 60 * 1000),
            x500Principal,
            keyPair.getPublic()
        ).build(signer);

        X509Certificate[] certChain = new X509Certificate[1];
        certChain[0] = new JcaX509CertificateConverter().getCertificate(certHolder);

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPass, certChain);

        String keystoreName = "ldap.keystore";
        File keystore = new File(directory, keystoreName);
        if (!keystore.createNewFile()) {
            throw new FileNotFoundException("Unable to create file:"+keystore);
        }
        keyStore.store(new FileOutputStream(keystore,false), keyPass);
        return keystore;
    }
}

