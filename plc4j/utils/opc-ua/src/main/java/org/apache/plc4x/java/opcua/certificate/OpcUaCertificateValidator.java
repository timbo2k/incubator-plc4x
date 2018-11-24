package org.apache.plc4x.java.opcua.certificate;

import com.google.common.collect.Sets;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.application.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.util.CertificateValidationUtil;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class OpcUaCertificateValidator implements CertificateValidator {

    private final Set<X509Certificate> trustedCertificates = Sets.newConcurrentHashSet();

    public OpcUaCertificateValidator(X509Certificate certificate) {
        trustedCertificates.add(certificate);
    }

    public OpcUaCertificateValidator(X509Certificate... certificates) {
        Collections.addAll(trustedCertificates, certificates);
    }

    @Override
    public void validate(X509Certificate certificate) throws UaException {
        CertificateValidationUtil.validateCertificateValidity(certificate);
    }

    @Override
    public void verifyTrustChain(List<X509Certificate> certificateChain) throws UaException {
        CertificateValidationUtil.verifyTrustChain(certificateChain, trustedCertificates, Sets.newHashSet());
    }

}
