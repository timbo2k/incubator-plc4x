package org.apache.plc4x.java.opcua;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Set;

import com.google.common.collect.Sets;
import org.eclipse.milo.opcua.stack.core.application.CertificateManager;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;

public class TestCertificateManager implements CertificateManager {

    private final KeyPair keyPair;
    private final X509Certificate certificate;

    public TestCertificateManager(KeyPair keyPair, X509Certificate certificate) {
        this.keyPair = keyPair;
        this.certificate = certificate;
    }

    @Override
    public Optional<KeyPair> getKeyPair(ByteString thumbprint) {
        return Optional.of(keyPair);
    }

    @Override
    public Optional<X509Certificate> getCertificate(ByteString thumbprint) {
        return Optional.of(certificate);
    }

    @Override
    public Optional<X509Certificate[]> getCertificateChain(ByteString thumbprint) {
        return getCertificate(thumbprint).map(c -> new X509Certificate[]{c});
    }

    @Override
    public Set<KeyPair> getKeyPairs() {
        return Sets.newHashSet(keyPair);
    }

    @Override
    public Set<X509Certificate> getCertificates() {
        return Sets.newHashSet(certificate);
    }

}

