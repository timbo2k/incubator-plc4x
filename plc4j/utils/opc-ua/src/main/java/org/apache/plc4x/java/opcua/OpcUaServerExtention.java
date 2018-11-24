package org.apache.plc4x.java.opcua;

import com.google.common.collect.ImmutableList;
import org.apache.plc4x.java.opcua.certificate.OpcUaCertificateManager;
import org.apache.plc4x.java.opcua.certificate.OpcUaCertificateValidator;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.identity.X509IdentityValidator;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.application.CertificateManager;
import org.eclipse.milo.opcua.stack.core.application.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import sun.security.x509.X509CertImpl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME;

/**
 * Created by timbo on 24.11.18
 */
public class OpcUaServerExtention {

    private CertificateValidator certificateValidator;
    private CertificateManager certificateManager;

    public OpcUaServerExtention() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        KeyPair keyPair = keyGen.generateKeyPair();
        X509Certificate x509Certificate = new X509CertImpl();
        this.certificateValidator = new OpcUaCertificateValidator();
        this.certificateManager = new OpcUaCertificateManager(keyPair,x509Certificate);
    }

    public void createOpcUaServer(){
        UsernameIdentityValidator identityValidator = new UsernameIdentityValidator(
            true,
            authChallenge -> {
                String username = authChallenge.getUsername();
                String password = authChallenge.getPassword();

                boolean userOk = "user".equals(username) && "password1".equals(password);
                boolean adminOk = "admin".equals(username) && "password2".equals(password);

                return userOk || adminOk;
            }
        );

        X509IdentityValidator x509IdentityValidator = new X509IdentityValidator(c -> true);

        List<String> bindAddresses = newArrayList();
        bindAddresses.add("0.0.0.0");

        List<String> endpointAddresses = newArrayList();
        endpointAddresses.add(HostnameUtil.getHostname());
        endpointAddresses.addAll(HostnameUtil.getHostnames("0.0.0.0"));

        // The configured application URI must match the one in the certificate(s)
        /*
        String applicationUri = certificateManager.getCertificates().stream()
            .findFirst()
            .map(certificate ->
                CertificateUtil.getSubjectAltNameField(certificate, CertificateUtil.SUBJECT_ALT_NAME_URI)
                    .map(Object::toString)
                    .orElseThrow(() -> new RuntimeException("certificate is missing the application URI")))
            .orElse("urn:eclipse:milo:examples:server:" + UUID.randomUUID());
            */

        OpcUaServerConfig config = OpcUaServerConfig.builder()
            .setApplicationUri("urn:eclipse:milo:examples:server:" + UUID.randomUUID())
            .setApplicationName(LocalizedText.english("Eclipse Milo OPC UA Example Server"))
            .setBindPort(12686)
            .setBindAddresses(bindAddresses)
            .setEndpointAddresses(endpointAddresses)
            .setBuildInfo(
                new BuildInfo(
                    "urn:eclipse:milo:example-server",
                    "eclipse",
                    "eclipse milo example server",
                    "abc",
                    "", DateTime.now()))
            .setCertificateManager(certificateManager)
            .setCertificateValidator(certificateValidator)
            .setIdentityValidator(new CompositeValidator(identityValidator, x509IdentityValidator))
            .setProductUri("urn:eclipse:milo:example-server")
            .setServerName("example")
            .setSecurityPolicies(
                EnumSet.of(
                    SecurityPolicy.None,
                    SecurityPolicy.Basic128Rsa15,
                    SecurityPolicy.Basic256,
                    SecurityPolicy.Basic256Sha256,
                    SecurityPolicy.Aes128_Sha256_RsaOaep,
                    SecurityPolicy.Aes256_Sha256_RsaPss))
            .setUserTokenPolicies(
                ImmutableList.of(
                    USER_TOKEN_POLICY_ANONYMOUS,
                    USER_TOKEN_POLICY_USERNAME))
            //USER_TOKEN_POLICY_X509))
            .build();


        OpcUaServer server = new OpcUaServer(config);
    }
}
