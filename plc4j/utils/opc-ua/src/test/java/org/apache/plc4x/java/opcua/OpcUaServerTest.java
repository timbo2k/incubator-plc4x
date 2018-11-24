package org.apache.plc4x.java.opcua;

import com.google.common.collect.ImmutableList;
import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.annotations.UaInputArgument;
import org.eclipse.milo.opcua.sdk.server.annotations.UaMethod;
import org.eclipse.milo.opcua.sdk.server.annotations.UaOutputArgument;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.identity.X509IdentityValidator;
import org.eclipse.milo.opcua.sdk.server.nodes.ServerNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaFolderNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.sdk.server.util.AnnotationBasedInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.application.CertificateManager;
import org.eclipse.milo.opcua.stack.core.application.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.*;
import org.eclipse.milo.opcua.stack.core.types.enumerated.NodeClass;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.Node;
import org.junit.Before;
import org.junit.Test;
import sun.security.x509.X509CertImpl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.*;

/**
 * Created by timbo on 24.11.18
 */
public class OpcUaServerTest {
    private CertificateManager certificateManager;
    private CertificateValidator certificateValidator;

    public static final String NAMESPACE_URI = "urn:eclipse:milo:hello-world";

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        KeyPair keyPair = keyGen.generateKeyPair();
        X509Certificate x509Certificate = new X509CertImpl();
        certificateManager = new TestCertificateManager(keyPair,x509Certificate);
        certificateValidator = new TestCertificateValidator();
    }

    // this test can'nt be run while other tests are running
    @Test
    public void testShutdownRemovesInstance2() throws ExecutionException, InterruptedException {
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

        server.getNamespaceManager().registerUri("abc:abc");

        int namespaceIndex = 1;

        NodeId folderNodeId = null;
        UaFolderNode folderNode = null;

        try {
            // Create a "HelloWorld" folder and add it to the node manager
            folderNodeId = new NodeId(namespaceIndex, "HelloWorld");

            folderNode = new UaFolderNode(
                server.getNodeMap(),
                folderNodeId,
                new QualifiedName(namespaceIndex, "HelloWorld"),
                LocalizedText.english("HelloWorld")
            );

            server.getNodeMap().addNode(folderNode);

            // Make sure our new folder shows up under the server's Objects folder
            server.getUaNamespace().addReference(
                Identifiers.ObjectsFolder,
                Identifiers.Organizes,
                true,
                folderNodeId.expanded(),
                NodeClass.Object
            );

        } catch (UaException e) {
            System.out.println("Error adding nodes: " + e.getMessage());
        }


        addMethodNode(folderNode,server,namespaceIndex);
        UaVariableNode variableNode = addVariableNode(folderNode,server,namespaceIndex);


        server.startup().get();

        Thread.sleep(5000);
        variableNode.setValue(new DataValue(new Variant("noch geiler Typ")));

        Thread.sleep(5000);
        variableNode.setValue(new DataValue(new Variant("noch noch geiler Typ")));

        Thread.sleep(5000);
        variableNode.setValue(new DataValue(new Variant("noch noch noch geiler Typ")));

        Thread.sleep(5000);
        variableNode.setValue(new DataValue(new Variant("noch noch noch noch geiler Typ")));

        Thread.sleep(10000);

        server.shutdown().get();
    }

    private UaVariableNode addVariableNode(UaFolderNode folderNode, OpcUaServer server, int namespaceIndex) {
        NodeId createdNode = new NodeId(namespaceIndex, "HelloWorld/Geiler");
        UaVariableNode variableNode = UaVariableNode.builder(server.getNodeMap())
            .setNodeId(createdNode)
            .setBrowseName(new QualifiedName(namespaceIndex, "geil"))
            .setDisplayName(new LocalizedText(null, "vollGeil"))
            .setDescription(
                LocalizedText.english("Geiler Typ."))
            .setDataType(Identifiers.String)
            .setValue(new DataValue(new Variant("geiler Typ")))
            .build();


        try {

            server.getNodeMap().addNode(variableNode);

            folderNode.addReference(new Reference(
                folderNode.getNodeId(),
                Identifiers.HasComponent,
                variableNode.getNodeId().expanded(),
                variableNode.getNodeClass(),
                true
            ));

            return variableNode;

        } catch (Exception e) {
            System.out.println("error");
        }
        return null;
    }

    private void addMethodNode(UaFolderNode folderNode, OpcUaServer server, int namespaceIndex) {

        UaMethodNode methodNode = UaMethodNode.builder(server.getNodeMap())
            .setNodeId(new NodeId(namespaceIndex, "HelloWorld/sqrt(x)"))
            .setBrowseName(new QualifiedName(namespaceIndex, "sqrt(x)"))
            .setDisplayName(new LocalizedText(null, "sqrt(x)"))
            .setDescription(
                LocalizedText.english("Returns the correctly rounded positive square root of a double value."))
            .build();


        try {
            AnnotationBasedInvocationHandler invocationHandler =
                AnnotationBasedInvocationHandler.fromAnnotatedObject(
                    server.getNodeMap(), new SqrtMethod());

            methodNode.setProperty(UaMethodNode.InputArguments, invocationHandler.getInputArguments());
            methodNode.setProperty(UaMethodNode.OutputArguments, invocationHandler.getOutputArguments());
            methodNode.setInvocationHandler(invocationHandler);

            server.getNodeMap().addNode(methodNode);

            folderNode.addReference(new Reference(
                folderNode.getNodeId(),
                Identifiers.HasComponent,
                methodNode.getNodeId().expanded(),
                methodNode.getNodeClass(),
                true
            ));

            methodNode.addReference(new Reference(
                methodNode.getNodeId(),
                Identifiers.HasComponent,
                folderNode.getNodeId().expanded(),
                folderNode.getNodeClass(),
                false
            ));
        } catch (Exception e) {
            System.out.println("error");
        }
    }

    private static final Object[][] STATIC_SCALAR_NODES = new Object[][]{
        {"Boolean", Identifiers.Boolean, new Variant(false)},
        {"Byte", Identifiers.Byte, new Variant(ubyte(0x00))},
        {"SByte", Identifiers.SByte, new Variant((byte) 0x00)},
        {"Integer", Identifiers.Integer, new Variant(32)},
        {"Int16", Identifiers.Int16, new Variant((short) 16)},
        {"Int32", Identifiers.Int32, new Variant(32)},
        {"Int64", Identifiers.Int64, new Variant(64L)},
        {"UInteger", Identifiers.UInteger, new Variant(uint(32))},
        {"UInt16", Identifiers.UInt16, new Variant(ushort(16))},
        {"UInt32", Identifiers.UInt32, new Variant(uint(32))},
        {"UInt64", Identifiers.UInt64, new Variant(ulong(64L))},
        {"Float", Identifiers.Float, new Variant(3.14f)},
        {"Double", Identifiers.Double, new Variant(3.14d)},
        {"String", Identifiers.String, new Variant("string value")},
        {"DateTime", Identifiers.DateTime, new Variant(DateTime.now())},
        {"Guid", Identifiers.Guid, new Variant(UUID.randomUUID())},
        {"ByteString", Identifiers.ByteString, new Variant(new ByteString(new byte[]{0x01, 0x02, 0x03, 0x04}))},
        {"XmlElement", Identifiers.XmlElement, new Variant(new XmlElement("<a>hello</a>"))},
        {"LocalizedText", Identifiers.LocalizedText, new Variant(LocalizedText.english("localized text"))},
        {"QualifiedName", Identifiers.QualifiedName, new Variant(new QualifiedName(1234, "defg"))},
        {"NodeId", Identifiers.NodeId, new Variant(new NodeId(1234, "abcd"))},

        {"Duration", Identifiers.Duration, new Variant(1.0)},
        {"UtcTime", Identifiers.UtcTime, new Variant(DateTime.now())},
    };

    private static final Object[][] STATIC_ARRAY_NODES = new Object[][]{
        {"BooleanArray", Identifiers.Boolean, false},
        {"ByteArray", Identifiers.Byte, ubyte(0)},
        {"SByteArray", Identifiers.SByte, (byte) 0x00},
        {"Int16Array", Identifiers.Int16, (short) 16},
        {"Int32Array", Identifiers.Int32, 32},
        {"Int64Array", Identifiers.Int64, 64L},
        {"UInt16Array", Identifiers.UInt16, ushort(16)},
        {"UInt32Array", Identifiers.UInt32, uint(32)},
        {"UInt64Array", Identifiers.UInt64, ulong(64L)},
        {"FloatArray", Identifiers.Float, 3.14f},
        {"DoubleArray", Identifiers.Double, 3.14d},
        {"StringArray", Identifiers.String, "string value"},
        {"DateTimeArray", Identifiers.DateTime, DateTime.now()},
        {"GuidArray", Identifiers.Guid, UUID.randomUUID()},
        {"ByteStringArray", Identifiers.ByteString, new ByteString(new byte[]{0x01, 0x02, 0x03, 0x04})},
        {"XmlElementArray", Identifiers.XmlElement, new XmlElement("<a>hello</a>")},
        {"LocalizedTextArray", Identifiers.LocalizedText, LocalizedText.english("localized text")},
        {"QualifiedNameArray", Identifiers.QualifiedName, new QualifiedName(1234, "defg")},
        {"NodeIdArray", Identifiers.NodeId, new NodeId(1234, "abcd")}
    };

    public class SqrtMethod {


        @UaMethod
        public void invoke(
            AnnotationBasedInvocationHandler.InvocationContext context,

            @UaInputArgument(
                name = "x",
                description = "A value.")
                Double x,

            @UaOutputArgument(
                name = "x_sqrt",
                description = "The positive square root of x. If the argument is NaN or less than zero, the result is NaN.")
                AnnotationBasedInvocationHandler.Out<Double> xSqrt) {

            System.out.println("sqrt(" + x.toString() + ")");

            xSqrt.set(Math.sqrt(x));
        }

    }

}