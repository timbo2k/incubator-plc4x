package org.apache.plc4x.java.opcua;

import org.eclipse.milo.opcua.stack.core.application.CertificateManager;
import org.eclipse.milo.opcua.stack.core.application.CertificateValidator;
import org.eclipse.milo.opcua.stack.server.config.UaTcpStackServerConfig;
import org.eclipse.milo.opcua.stack.server.tcp.SocketServers;
import org.eclipse.milo.opcua.stack.server.tcp.UaTcpStackServer;
import org.junit.Before;
import org.junit.Test;
import sun.security.x509.X509CertImpl;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;


import static org.junit.Assert.*;

/**
 * Created by timbo on 24.11.18
 */
public class OpcUaServerTest {
    private CertificateManager certificateManager;
    private CertificateValidator certificateValidator;

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
    public void testShutdownRemovesInstance() throws ExecutionException, InterruptedException {
        UaTcpStackServerConfig config = UaTcpStackServerConfig.builder()
            .setServerName("test")
            .setCertificateManager(certificateManager)
            .setCertificateValidator(certificateValidator)
            .build();

        UaTcpStackServer server = new UaTcpStackServer(config);

        server.addEndpoint("opc.tcp://localhost:12685/test", null);

        server.startup().get();

        //assertFalse(SocketServers.SERVERS.isEmpty());
        Thread.sleep(10000);
        server.shutdown().get();
        //assertTrue(SocketServers.SERVERS.isEmpty());
    }

}