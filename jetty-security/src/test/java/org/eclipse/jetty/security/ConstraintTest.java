//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.HttpConstraintElement;
import javax.servlet.HttpMethodConstraintElement;
import javax.servlet.ServletException;
import javax.servlet.ServletSecurityElement;
import javax.servlet.annotation.ServletSecurity.EmptyRoleSemantic;
import javax.servlet.annotation.ServletSecurity.TransportGuarantee;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.security.authentication.DigestAuthenticator;
import org.eclipse.jetty.security.authentication.FormAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerWrapper;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.util.B64Code;
import org.eclipse.jetty.util.TypeUtil;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Password;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ConstraintTest
{
    private static final String TEST_REALM = "TestRealm";
    private Server _server;
    private LocalConnector _connector;
    private ConstraintSecurityHandler _security;
    private HttpConfiguration _config;

    @Before
    public void startServer()
    {
        _server = new Server();
        _connector = new LocalConnector(_server);
        _config=_connector.getConnectionFactory(HttpConnectionFactory.class).getHttpConfiguration();
        _server.setConnectors(new Connector[]{_connector});

        ContextHandler _context = new ContextHandler();
        SessionHandler _session = new SessionHandler();

        HashLoginService _loginService = new HashLoginService(TEST_REALM);
        _loginService.putUser("user0", new Password("password"), new String[]{});
        _loginService.putUser("user",new Password("password"), new String[] {"user"});
        _loginService.putUser("user2",new Password("password"), new String[] {"user"});
        _loginService.putUser("admin",new Password("password"), new String[] {"user","administrator"});
        _loginService.putUser("user3", new Password("password"), new String[] {"foo"});
        

        _context.setContextPath("/ctx");
        _server.setHandler(_context);
        _context.setHandler(_session);

        _server.addBean(_loginService);

        _security = new ConstraintSecurityHandler();
        _session.setHandler(_security);
        RequestHandler _handler = new RequestHandler();
        _security.setHandler(_handler);

        _security.setConstraintMappings(getConstraintMappings(), getKnownRoles());
    }

    @After
    public void stopServer() throws Exception
    {
        _server.stop();
    }

    public Set<String> getKnownRoles()
    {
        Set<String> knownRoles=new HashSet<>();
        knownRoles.add("user");
        knownRoles.add("administrator");

        return knownRoles;
    }

    private List<ConstraintMapping> getConstraintMappings()
    {
        Constraint constraint0 = new Constraint();
        constraint0.setAuthenticate(true);
        constraint0.setName("forbid");
        ConstraintMapping mapping0 = new ConstraintMapping();
        mapping0.setPathSpec("/forbid/*");
        mapping0.setConstraint(constraint0);

        Constraint constraint1 = new Constraint();
        constraint1.setAuthenticate(true);
        constraint1.setName("auth");
        constraint1.setRoles(new String[]{Constraint.ANY_ROLE});
        ConstraintMapping mapping1 = new ConstraintMapping();
        mapping1.setPathSpec("/auth/*");
        mapping1.setConstraint(constraint1);

        Constraint constraint2 = new Constraint();
        constraint2.setAuthenticate(true);
        constraint2.setName("admin");
        constraint2.setRoles(new String[]{"administrator"});
        ConstraintMapping mapping2 = new ConstraintMapping();
        mapping2.setPathSpec("/admin/*");
        mapping2.setConstraint(constraint2);
        mapping2.setMethod("GET");

        Constraint constraint3 = new Constraint();
        constraint3.setAuthenticate(false);
        constraint3.setName("relax");
        ConstraintMapping mapping3 = new ConstraintMapping();
        mapping3.setPathSpec("/admin/relax/*");
        mapping3.setConstraint(constraint3);

        Constraint constraint4 = new Constraint();
        constraint4.setAuthenticate(true);
        constraint4.setName("loginpage");
        constraint4.setRoles(new String[]{"administrator"});
        ConstraintMapping mapping4 = new ConstraintMapping();
        mapping4.setPathSpec("/testLoginPage");
        mapping4.setConstraint(constraint4);

        Constraint constraint5 = new Constraint();
        constraint5.setAuthenticate(false);
        constraint5.setName("allow forbidden POST");
        ConstraintMapping mapping5 = new ConstraintMapping();
        mapping5.setPathSpec("/forbid/post");
        mapping5.setConstraint(constraint5);
        mapping5.setMethod("POST");

        Constraint constraint6 = new Constraint();
        constraint6.setAuthenticate(false);
        constraint6.setName("data constraint");
        constraint6.setDataConstraint(2);
        ConstraintMapping mapping6 = new ConstraintMapping();
        mapping6.setPathSpec("/data/*");
        mapping6.setConstraint(constraint6);
        
        Constraint constraint7 = new Constraint();
        constraint7.setAuthenticate(true);
        constraint7.setName("** constraint");
        constraint7.setRoles(new String[]{Constraint.ANY_AUTH,"user"}); //the "user" role is superfluous once ** has been defined
        ConstraintMapping mapping7 = new ConstraintMapping();
        mapping7.setPathSpec("/starstar/*");
        mapping7.setConstraint(constraint7);
       
        
        return Arrays.asList(mapping0, mapping1, mapping2, mapping3, mapping4, mapping5, mapping6, mapping7);
    }

    @Test
    public void testConstraints() throws Exception
    {
        List<ConstraintMapping> mappings = new ArrayList<>(_security.getConstraintMappings());

        Assert.assertTrue(mappings.get(0).getConstraint().isForbidden());
        Assert.assertFalse(mappings.get(1).getConstraint().isForbidden());
        Assert.assertFalse(mappings.get(2).getConstraint().isForbidden());
        Assert.assertFalse(mappings.get(3).getConstraint().isForbidden());

        Assert.assertFalse(mappings.get(0).getConstraint().isAnyRole());
        Assert.assertTrue(mappings.get(1).getConstraint().isAnyRole());
        Assert.assertFalse(mappings.get(2).getConstraint().isAnyRole());
        Assert.assertFalse(mappings.get(3).getConstraint().isAnyRole());

        Assert.assertFalse(mappings.get(0).getConstraint().hasRole("administrator"));
        Assert.assertTrue(mappings.get(1).getConstraint().hasRole("administrator"));
        Assert.assertTrue(mappings.get(2).getConstraint().hasRole("administrator"));
        Assert.assertFalse(mappings.get(3).getConstraint().hasRole("administrator"));

        Assert.assertTrue(mappings.get(0).getConstraint().getAuthenticate());
        Assert.assertTrue(mappings.get(1).getConstraint().getAuthenticate());
        Assert.assertTrue(mappings.get(2).getConstraint().getAuthenticate());
        Assert.assertFalse(mappings.get(3).getConstraint().getAuthenticate());
    }
    

    /**
     * Equivalent of Servlet Spec 3.1 pg 132, sec 13.4.1.1, Example 13-1
     * &#064;ServletSecurity
     * @throws Exception if test fails
     */
    @Test
    public void testSecurityElementExample13_1() throws Exception
    {
        ServletSecurityElement element = new ServletSecurityElement();
        List<ConstraintMapping> mappings = ConstraintSecurityHandler.createConstraintsWithMappingsForPath("foo", "/foo/*", element);
        Assert.assertTrue(mappings.isEmpty());
    }
    
   
    /**
     * Equivalent of Servlet Spec 3.1 pg 132, sec 13.4.1.1, Example 13-2
     * &#064;ServletSecurity(@HttpConstraint(transportGuarantee = TransportGuarantee.CONFIDENTIAL))
     * 
     * @throws Exception if test fails
     */
    @Test
    public void testSecurityElementExample13_2() throws Exception
    {
        HttpConstraintElement httpConstraintElement = new HttpConstraintElement(TransportGuarantee.CONFIDENTIAL);
        ServletSecurityElement element = new ServletSecurityElement(httpConstraintElement);
        List<ConstraintMapping> mappings = ConstraintSecurityHandler.createConstraintsWithMappingsForPath("foo", "/foo/*", element);
        Assert.assertTrue(!mappings.isEmpty());
        Assert.assertEquals(1, mappings.size());
        ConstraintMapping mapping = mappings.get(0);
        Assert.assertEquals(2, mapping.getConstraint().getDataConstraint());
    }
    
    /**
     * Equivalent of Servlet Spec 3.1 pg 132, sec 13.4.1.1, Example 13-3
     * @ServletSecurity(@HttpConstraint(EmptyRoleSemantic.DENY))
     * @throws Exception if test fails
     */
    @Test
    public void testSecurityElementExample13_3() throws Exception
    {
        HttpConstraintElement httpConstraintElement = new HttpConstraintElement(EmptyRoleSemantic.DENY);
        ServletSecurityElement element = new ServletSecurityElement(httpConstraintElement);
        List<ConstraintMapping> mappings = ConstraintSecurityHandler.createConstraintsWithMappingsForPath("foo", "/foo/*", element);
        Assert.assertTrue(!mappings.isEmpty());
        Assert.assertEquals(1, mappings.size());
        ConstraintMapping mapping = mappings.get(0);
        Assert.assertTrue(mapping.getConstraint().isForbidden());
    }
    
    /**
     * Equivalent of Servlet Spec 3.1 pg 132, sec 13.4.1.1, Example 13-4
     * @ServletSecurity(@HttpConstraint(rolesAllowed = "R1"))
     * @throws Exception if test fails
     */
    @Test
    public void testSecurityElementExample13_4() throws Exception
    {
        HttpConstraintElement httpConstraintElement = new HttpConstraintElement(TransportGuarantee.NONE, "R1");
        ServletSecurityElement element = new ServletSecurityElement(httpConstraintElement);
        List<ConstraintMapping> mappings = ConstraintSecurityHandler.createConstraintsWithMappingsForPath("foo", "/foo/*", element);
        Assert.assertTrue(!mappings.isEmpty());
        Assert.assertEquals(1, mappings.size());
        ConstraintMapping mapping = mappings.get(0);
        Assert.assertTrue(mapping.getConstraint().getAuthenticate());
        Assert.assertTrue(mapping.getConstraint().getRoles() != null);
        Assert.assertEquals(1, mapping.getConstraint().getRoles().length);
        Assert.assertEquals("R1", mapping.getConstraint().getRoles()[0]);
        Assert.assertEquals(0, mapping.getConstraint().getDataConstraint());
    }
    
    /**
     * Equivalent of Servlet Spec 3.1 pg 132, sec 13.4.1.1, Example 13-5
     * @ServletSecurity((httpMethodConstraints = {
     * @HttpMethodConstraint(value = "GET", rolesAllowed = "R1"),
     * @HttpMethodConstraint(value = "POST", rolesAllowed = "R1",
     *         transportGuarantee = TransportGuarantee.CONFIDENTIAL)})
     * @throws Exception if test fails
     */ 
    @Test
    public void testSecurityElementExample13_5() throws Exception
    {
        List<HttpMethodConstraintElement> methodElements = new ArrayList<HttpMethodConstraintElement>();
        methodElements.add(new HttpMethodConstraintElement("GET", new HttpConstraintElement(TransportGuarantee.NONE, "R1")));
        methodElements.add(new HttpMethodConstraintElement("POST", new HttpConstraintElement(TransportGuarantee.CONFIDENTIAL, "R1")));
        ServletSecurityElement element = new ServletSecurityElement(methodElements);
        List<ConstraintMapping> mappings = ConstraintSecurityHandler.createConstraintsWithMappingsForPath("foo", "/foo/*", element);
        Assert.assertTrue(!mappings.isEmpty());
        Assert.assertEquals(2, mappings.size());
        Assert.assertEquals("GET", mappings.get(0).getMethod());
        Assert.assertEquals("R1", mappings.get(0).getConstraint().getRoles()[0]);
        Assert.assertTrue(mappings.get(0).getMethodOmissions() == null);
        Assert.assertEquals(0, mappings.get(0).getConstraint().getDataConstraint());
        Assert.assertEquals("POST", mappings.get(1).getMethod());
        Assert.assertEquals("R1", mappings.get(1).getConstraint().getRoles()[0]);
        Assert.assertEquals(2, mappings.get(1).getConstraint().getDataConstraint());
        Assert.assertTrue(mappings.get(1).getMethodOmissions() == null);
    }
    
    /**
     * Equivalent of Servlet Spec 3.1 pg 132, sec 13.4.1.1, Example 13-6
     * @ServletSecurity(value = @HttpConstraint(rolesAllowed = "R1"), httpMethodConstraints = @HttpMethodConstraint("GET"))
     * @throws Exception if test fails
     */
    @Test
    public void testSecurityElementExample13_6 () throws Exception
    {
        List<HttpMethodConstraintElement> methodElements = new ArrayList<HttpMethodConstraintElement>();
        methodElements.add(new HttpMethodConstraintElement("GET"));
        ServletSecurityElement element = new ServletSecurityElement(new HttpConstraintElement(TransportGuarantee.NONE, "R1"), methodElements);
        List<ConstraintMapping> mappings = ConstraintSecurityHandler.createConstraintsWithMappingsForPath("foo", "/foo/*", element);
        Assert.assertTrue(!mappings.isEmpty());
        Assert.assertEquals(2, mappings.size());
        Assert.assertTrue(mappings.get(0).getMethodOmissions() != null);
        Assert.assertEquals("GET", mappings.get(0).getMethodOmissions()[0]);
        Assert.assertTrue(mappings.get(0).getConstraint().getAuthenticate());
        Assert.assertEquals("R1", mappings.get(0).getConstraint().getRoles()[0]);
        Assert.assertEquals("GET", mappings.get(1).getMethod());
        Assert.assertTrue(mappings.get(1).getMethodOmissions() == null);
        Assert.assertEquals(0, mappings.get(1).getConstraint().getDataConstraint());
        Assert.assertFalse(mappings.get(1).getConstraint().getAuthenticate());
    }
    
    /**
     * Equivalent of Servlet Spec 3.1 pg 132, sec 13.4.1.1, Example 13-7
     * @ServletSecurity(value = @HttpConstraint(rolesAllowed = "R1"), 
     *                  httpMethodConstraints = @HttpMethodConstraint(value="TRACE",
     *                  emptyRoleSemantic = EmptyRoleSemantic.DENY))
     * @throws Exception if test fails
     */
    @Test
    public void testSecurityElementExample13_7() throws Exception
    {
        List<HttpMethodConstraintElement> methodElements = new ArrayList<HttpMethodConstraintElement>();
        methodElements.add(new HttpMethodConstraintElement("TRACE", new HttpConstraintElement(EmptyRoleSemantic.DENY)));
        ServletSecurityElement element = new ServletSecurityElement(new HttpConstraintElement(TransportGuarantee.NONE, "R1"), methodElements);
        List<ConstraintMapping> mappings = ConstraintSecurityHandler.createConstraintsWithMappingsForPath("foo", "/foo/*", element);
        Assert.assertTrue(!mappings.isEmpty());
        Assert.assertEquals(2, mappings.size());
        Assert.assertTrue(mappings.get(0).getMethodOmissions() != null);
        Assert.assertEquals("TRACE", mappings.get(0).getMethodOmissions()[0]);
        Assert.assertTrue(mappings.get(0).getConstraint().getAuthenticate());
        Assert.assertEquals("R1", mappings.get(0).getConstraint().getRoles()[0]);
        Assert.assertEquals("TRACE", mappings.get(1).getMethod());
        Assert.assertTrue(mappings.get(1).getMethodOmissions() == null);
        Assert.assertEquals(0, mappings.get(1).getConstraint().getDataConstraint());
        Assert.assertTrue(mappings.get(1).getConstraint().isForbidden());
    }
    
    @Test
    public void testUncoveredHttpMethodDetection() throws Exception
    {
        //Test no methods named
        Constraint constraint1 = new Constraint();
        constraint1.setAuthenticate(true);
        constraint1.setName("** constraint");
        constraint1.setRoles(new String[]{Constraint.ANY_AUTH,"user"}); //No methods named, no uncovered methods
        ConstraintMapping mapping1 = new ConstraintMapping();
        mapping1.setPathSpec("/starstar/*");
        mapping1.setConstraint(constraint1);
        
        _security.setConstraintMappings(Collections.singletonList(mapping1));
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        Set<String> uncoveredPaths = _security.getPathsWithUncoveredHttpMethods();
        Assert.assertTrue(uncoveredPaths.isEmpty()); //no uncovered methods
  
        //Test only an explicitly named method, no omissions to cover other methods
        Constraint constraint2 = new Constraint();
        constraint2.setAuthenticate(true);
        constraint2.setName("user constraint");
        constraint2.setRoles(new String[]{"user"});
        ConstraintMapping mapping2 = new ConstraintMapping();
        mapping2.setPathSpec("/user/*");
        mapping2.setMethod("GET");
        mapping2.setConstraint(constraint2);
        
        _security.addConstraintMapping(mapping2);
        uncoveredPaths = _security.getPathsWithUncoveredHttpMethods();
        Assert.assertNotNull(uncoveredPaths);
        Assert.assertEquals(1, uncoveredPaths.size());
        Assert.assertTrue(uncoveredPaths.contains("/user/*"));
        
        //Test an explicitly named method with a http-method-omission to cover all other methods
        Constraint constraint2a = new Constraint();
        constraint2a.setAuthenticate(true);
        constraint2a.setName("forbid constraint");
        ConstraintMapping mapping2a = new ConstraintMapping();
        mapping2a.setPathSpec("/user/*");
        mapping2a.setMethodOmissions(new String[]{"GET"});
        mapping2a.setConstraint(constraint2a);
        
        _security.addConstraintMapping(mapping2a);
        uncoveredPaths = _security.getPathsWithUncoveredHttpMethods();
        Assert.assertNotNull(uncoveredPaths);
        Assert.assertEquals(0, uncoveredPaths.size());
        
        //Test a http-method-omission only
        Constraint constraint3 = new Constraint();
        constraint3.setAuthenticate(true);
        constraint3.setName("omit constraint");
        ConstraintMapping mapping3 = new ConstraintMapping();
        mapping3.setPathSpec("/omit/*");
        mapping3.setMethodOmissions(new String[]{"GET", "POST"});
        mapping3.setConstraint(constraint3);
        
        _security.addConstraintMapping(mapping3);
        uncoveredPaths = _security.getPathsWithUncoveredHttpMethods();
        Assert.assertNotNull(uncoveredPaths);
        Assert.assertTrue(uncoveredPaths.contains("/omit/*"));
        
        _security.setDenyUncoveredHttpMethods(true);
        uncoveredPaths = _security.getPathsWithUncoveredHttpMethods();
        Assert.assertNotNull(uncoveredPaths);
        Assert.assertEquals(0, uncoveredPaths.size());
    }

    @Test
    public void testBasic() throws Exception
    {
        List<ConstraintMapping> list = new ArrayList<>(_security.getConstraintMappings());
        
        Constraint constraint6 = new Constraint();
        constraint6.setAuthenticate(true);
        constraint6.setName("omit HEAD and GET");
        constraint6.setRoles(new String[]{"user"});
        ConstraintMapping mapping6 = new ConstraintMapping();
        mapping6.setPathSpec("/omit/*");
        mapping6.setConstraint(constraint6);
        mapping6.setMethodOmissions(new String[]{"GET", "HEAD"}); //requests for every method except GET and HEAD must be in role "user"
        list.add(mapping6);
        
        Constraint constraint7 = new Constraint();
        constraint7.setAuthenticate(true);
        constraint7.setName("non-omitted GET");
        constraint7.setRoles(new String[]{"administrator"});
        ConstraintMapping mapping7 = new ConstraintMapping();
        mapping7.setPathSpec("/omit/*");
        mapping7.setConstraint(constraint7);
        mapping7.setMethod("GET"); //requests for GET must be in role "admin"
        list.add(mapping7);
        
        Constraint constraint8 = new Constraint();
        constraint8.setAuthenticate(true);
        constraint8.setName("non specific");
        constraint8.setRoles(new String[]{"foo"});
        ConstraintMapping mapping8 = new ConstraintMapping();
        mapping8.setPathSpec("/omit/*");
        mapping8.setConstraint(constraint8);//requests for all methods must be in role "foo"
        list.add(mapping8);
        
        Set<String> knownRoles=new HashSet<>();
        knownRoles.add("user");
        knownRoles.add("administrator");
        knownRoles.add("foo");

        _security.setConstraintMappings(list, knownRoles);
        
        
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
   
        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user:wrong") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user:password") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        
        // test admin
        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("admin:wrong") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user:password") + "\r\n" +
                "\r\n");

        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));
        Assert.assertThat(response, Matchers.containsString("!role"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("admin:password") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/admin/relax/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        
        //check GET is in role administrator 
        response = _connector.getResponses("GET /ctx/omit/x HTTP/1.0\r\n" +
                                           "Authorization: Basic " + B64Code.encode("admin:password") + "\r\n" +
                                           "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        
        //check POST is in role user
        response = _connector.getResponses("POST /ctx/omit/x HTTP/1.0\r\n" +
                                           "Authorization: Basic " + B64Code.encode("user2:password") + "\r\n" +
                                           "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        
        //check POST can be in role foo too      
        response = _connector.getResponses("POST /ctx/omit/x HTTP/1.0\r\n" +
                                           "Authorization: Basic " + B64Code.encode("user3:password") + "\r\n" +
                                           "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        
        //check HEAD cannot be in role user
        response = _connector.getResponses("HEAD /ctx/omit/x HTTP/1.0\r\n" +
                                           "Authorization: Basic " + B64Code.encode("user2:password") + "\r\n" +
                                           "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));
    }

    
    private static String CNONCE="1234567890";
    private String digest(String nonce, String username,String password,String uri,String nc) throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] ha1;
        // calc A1 digest
        md.update(username.getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update("TestRealm".getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update(password.getBytes(StandardCharsets.ISO_8859_1));
        ha1 = md.digest();
        // calc A2 digest
        md.reset();
        md.update("GET".getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update(uri.getBytes(StandardCharsets.ISO_8859_1));
        byte[] ha2 = md.digest();

        // calc digest
        // request-digest = <"> < KD ( H(A1), unq(nonce-value) ":"
        // nc-value ":" unq(cnonce-value) ":" unq(qop-value) ":" H(A2) )
        // <">
        // request-digest = <"> < KD ( H(A1), unq(nonce-value) ":" H(A2)
        // ) > <">

        md.update(TypeUtil.toString(ha1, 16).getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update(nonce.getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update(nc.getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update(CNONCE.getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update("auth".getBytes(StandardCharsets.ISO_8859_1));
        md.update((byte) ':');
        md.update(TypeUtil.toString(ha2, 16).getBytes(StandardCharsets.ISO_8859_1));
        byte[] digest = md.digest();

        // check digest
        return TypeUtil.toString(digest, 16);
    }
    
    @Test
    public void testDigest() throws Exception
    {
        DigestAuthenticator authenticator = new DigestAuthenticator();
        authenticator.setMaxNonceCount(5);
        _security.setAuthenticator(authenticator);
        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
   
        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: Digest realm=\"TestRealm\""));

        Pattern nonceP = Pattern.compile("nonce=\"([^\"]*)\",");
        Matcher matcher = nonceP.matcher(response);
        Assert.assertTrue(matcher.find());
        String nonce=matcher.group(1);
        
        
        //wrong password
        String digest= digest(nonce,"user","WRONG","/ctx/auth/info","1");
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
            "Authorization: Digest username=\"user\", qop=auth, cnonce=\"1234567890\", uri=\"/ctx/auth/info\", realm=\"TestRealm\", "+
            "nc=1, "+
            "nonce=\""+nonce+"\", "+
            "response=\""+digest+"\"\r\n"+
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        
        // right password
        digest= digest(nonce,"user","password","/ctx/auth/info","2");
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
            "Authorization: Digest username=\"user\", qop=auth, cnonce=\"1234567890\", uri=\"/ctx/auth/info\", realm=\"TestRealm\", "+
            "nc=2, "+
            "nonce=\""+nonce+"\", "+
            "response=\""+digest+"\"\r\n"+
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        

        // once only
        digest= digest(nonce,"user","password","/ctx/auth/info","2");
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
            "Authorization: Digest username=\"user\", qop=auth, cnonce=\"1234567890\", uri=\"/ctx/auth/info\", realm=\"TestRealm\", "+
            "nc=2, "+
            "nonce=\""+nonce+"\", "+
            "response=\""+digest+"\"\r\n"+
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));

        // increasing
        digest= digest(nonce,"user","password","/ctx/auth/info","4");
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
            "Authorization: Digest username=\"user\", qop=auth, cnonce=\"1234567890\", uri=\"/ctx/auth/info\", realm=\"TestRealm\", "+
            "nc=4, "+
            "nonce=\""+nonce+"\", "+
            "response=\""+digest+"\"\r\n"+
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        
        // out of order
        digest= digest(nonce,"user","password","/ctx/auth/info","3");
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
            "Authorization: Digest username=\"user\", qop=auth, cnonce=\"1234567890\", uri=\"/ctx/auth/info\", realm=\"TestRealm\", "+
            "nc=3, "+
            "nonce=\""+nonce+"\", "+
            "response=\""+digest+"\"\r\n"+
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        
        // stale
        digest= digest(nonce,"user","password","/ctx/auth/info","5");
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
            "Authorization: Digest username=\"user\", qop=auth, cnonce=\"1234567890\", uri=\"/ctx/auth/info\", realm=\"TestRealm\", "+
            "nc=5, "+
            "nonce=\""+nonce+"\", "+
            "response=\""+digest+"\"\r\n"+
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("stale=true"));
    }


    @Test
    public void testFormDispatch() throws Exception
    {
        _security.setAuthenticator(new FormAuthenticator("/testLoginPage","/testErrorPage",true));
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.containsString("Cache-Control: no-cache"));
        Assert.assertThat(response, Matchers.containsString("Expires"));
        Assert.assertThat(response, Matchers.containsString("URI=/ctx/testLoginPage"));

        String session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 31\r\n" +
                "\r\n" +
        "j_username=user&j_password=wrong\r\n");
        Assert.assertThat(response, Matchers.containsString("testErrorPage"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 35\r\n" +
                "\r\n" +
                "j_username=user&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));


        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));
    }

    @Test
    public void testFormRedirect() throws Exception
    {
        _security.setAuthenticator(new FormAuthenticator("/testLoginPage","/testErrorPage",false));
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.containsString(" 302 Found"));
        Assert.assertThat(response, Matchers.containsString("/ctx/testLoginPage"));
        String session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/testLoginPage HTTP/1.0\r\n"+
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.containsString(" 200 OK"));
        Assert.assertThat(response, Matchers.containsString("URI=/ctx/testLoginPage"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 32\r\n" +
                "\r\n" +
                "j_username=user&j_password=wrong");
        Assert.assertThat(response, Matchers.containsString("Location"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 35\r\n" +
                "\r\n" +
                "j_username=user&j_password=password");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));
    }

    @Test
    public void testFormPostRedirect() throws Exception
    {
        _security.setAuthenticator(new FormAuthenticator("/testLoginPage","/testErrorPage",false));
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));

        response = _connector.getResponses("POST /ctx/auth/info HTTP/1.0\r\n"+
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 27\r\n" +
                "\r\n" +
                "test_parameter=test_value\r\n");
        Assert.assertThat(response, Matchers.containsString(" 302 Found"));
        Assert.assertThat(response, Matchers.containsString("/ctx/testLoginPage"));
        String session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/testLoginPage HTTP/1.0\r\n"+
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.containsString(" 200 OK"));
        Assert.assertThat(response, Matchers.containsString("URI=/ctx/testLoginPage"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 31\r\n" +
                "\r\n" +
        "j_username=user&j_password=wrong\r\n");
        
        Assert.assertThat(response, Matchers.containsString("Location"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 35\r\n" +
                "\r\n" +
                "j_username=user&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        // sneak in other request
        response = _connector.getResponses("GET /ctx/auth/other HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        Assert.assertTrue(!response.contains("test_value"));

        // retry post as GET
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        Assert.assertTrue(response.contains("test_value"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));
    }

    @Test
    public void testFormNoCookies() throws Exception
    {
        _security.setAuthenticator(new FormAuthenticator("/testLoginPage","/testErrorPage",false));
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.containsString(" 302 Found"));
        Assert.assertThat(response, Matchers.containsString("/ctx/testLoginPage"));
        int jsession=response.indexOf(";jsessionid=");
        String session = response.substring(jsession + 12, response.indexOf("\r\n",jsession));

        response = _connector.getResponses("GET /ctx/testLoginPage;jsessionid="+session+";other HTTP/1.0\r\n"+
                "\r\n");
        Assert.assertThat(response, Matchers.containsString(" 200 OK"));
        Assert.assertThat(response, Matchers.containsString("URI=/ctx/testLoginPage"));

        response = _connector.getResponses("POST /ctx/j_security_check;jsessionid="+session+";other HTTP/1.0\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 31\r\n" +
                "\r\n" +
        "j_username=user&j_password=wrong\r\n");
        Assert.assertThat(response, Matchers.containsString("Location"));

        response = _connector.getResponses("POST /ctx/j_security_check;jsessionid="+session+";other HTTP/1.0\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 35\r\n" +
                "\r\n" +
                "j_username=user&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info;jsessionid="+session+";other HTTP/1.0\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/admin/info;jsessionid="+session+";other HTTP/1.0\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));
    }

    @Test
    public void testStrictBasic() throws Exception
    {
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user:wrong") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user3:password") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user2:password") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));


        // test admin
        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("admin:wrong") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 Unauthorized"));
        Assert.assertThat(response, Matchers.containsString("WWW-Authenticate: basic realm=\"TestRealm\""));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user:password") + "\r\n" +
                "\r\n");

        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));
        Assert.assertThat(response, Matchers.containsString("!role"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("admin:password") + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));


        response = _connector.getResponses("GET /ctx/admin/relax/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
    }

    @Test
    public void testStrictFormDispatch()
            throws Exception
    {
        _security.setAuthenticator(new FormAuthenticator("/testLoginPage","/testErrorPage",true));
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        // assertThat(response,containsString(" 302 Found"));
        // assertThat(response,containsString("/ctx/testLoginPage"));
        Assert.assertThat(response, Matchers.containsString("Cache-Control: no-cache"));
        Assert.assertThat(response, Matchers.containsString("Expires"));
        Assert.assertThat(response, Matchers.containsString("URI=/ctx/testLoginPage"));

        String session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 31\r\n" +
                "\r\n" +
                "j_username=user&j_password=wrong\r\n");
        // assertThat(response,containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("testErrorPage"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 36\r\n" +
                "\r\n" +
                "j_username=user0&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));



        // log in again as user2
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
//        assertThat(response,startsWith("HTTP/1.1 302 "));
//        assertThat(response,containsString("testLoginPage"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 36\r\n" +
                "\r\n" +
                "j_username=user2&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));



        // log in again as admin
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
//        assertThat(response,startsWith("HTTP/1.1 302 "));
//        assertThat(response,containsString("testLoginPage"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 36\r\n" +
                "\r\n" +
                "j_username=admin&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
    }

    @Test
    public void testStrictFormRedirect() throws Exception
    {
        _security.setAuthenticator(new FormAuthenticator("/testLoginPage","/testErrorPage",false));
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/forbid/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 Forbidden"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\nHost:wibble.com:8888\r\n\r\n");
        Assert.assertThat(response, Matchers.containsString(" 302 Found"));
        Assert.assertThat(response, Matchers.containsString("http://wibble.com:8888/ctx/testLoginPage"));

        String session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 31\r\n" +
                "\r\n" +
                "j_username=user&j_password=wrong\r\n");
        Assert.assertThat(response, Matchers.containsString("Location"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 36\r\n" +
                "\r\n" +
                "j_username=user3&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));



        // log in again as user2
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("testLoginPage"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 36\r\n" +
                "\r\n" +
                "j_username=user2&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));


        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        //check user2 does not have right role to access /admin/*
        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        Assert.assertThat(response, Matchers.containsString("!role"));
        
        //log in as user3, who doesn't have a valid role, but we are checking a constraint
        //of ** which just means they have to be authenticated
        response = _connector.getResponses("GET /ctx/starstar/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("testLoginPage"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 36\r\n" +
                "\r\n" +
                "j_username=user3&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/starstar/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/starstar/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));


        // log in again as admin
        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n\r\n");
//        assertThat(response,startsWith("HTTP/1.1 302 "));
//        assertThat(response,containsString("testLoginPage"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("POST /ctx/j_security_check HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: 36\r\n" +
                "\r\n" +
                "j_username=admin&j_password=password\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 "));
        Assert.assertThat(response, Matchers.containsString("Location"));
        Assert.assertThat(response, Matchers.containsString("/ctx/auth/info"));
        session = response.substring(response.indexOf("JSESSIONID=") + 11, response.indexOf(";Path=/ctx"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/admin/info HTTP/1.0\r\n" +
                "Cookie: JSESSIONID=" + session + "\r\n" +
                "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
    }



    @Test
    public void testDataRedirection() throws Exception
    {
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/data/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403"));
        
        _config.setSecurePort(8443);
        _config.setSecureScheme("https");

        response = _connector.getResponses("GET /ctx/data/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 Found"));
        Assert.assertTrue(response.indexOf("Location") > 0);
        Assert.assertTrue(response.indexOf(":8443/ctx/data/info") > 0);

        _config.setSecurePort(443);
        response = _connector.getResponses("GET /ctx/data/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 Found"));
        Assert.assertTrue(response.indexOf("Location") > 0);
        Assert.assertTrue(!response.contains(":443/ctx/data/info"));

        _config.setSecurePort(8443);
        response = _connector.getResponses("GET /ctx/data/info HTTP/1.0\r\nHost: wobble.com\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 Found"));
        Assert.assertTrue(response.indexOf("Location") > 0);
        Assert.assertTrue(response.indexOf("https://wobble.com:8443/ctx/data/info") > 0);

        _config.setSecurePort(443);
        response = _connector.getResponses("GET /ctx/data/info HTTP/1.0\r\nHost: wobble.com\r\n\r\n");
        System.err.println(response);
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 302 Found"));
        Assert.assertTrue(response.indexOf("Location") > 0);
        Assert.assertTrue(!response.contains(":443"));
        Assert.assertTrue(response.indexOf("https://wobble.com/ctx/data/info") > 0);
    }
    
    @Test
    public void testRoleRef() throws Exception
    {
        RoleCheckHandler check=new RoleCheckHandler();
        _security.setHandler(check);
        _security.setAuthenticator(new BasicAuthenticator());

        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n\r\n", 100000, TimeUnit.MILLISECONDS);
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user2:password") + "\r\n" +
                "\r\n", 100000, TimeUnit.MILLISECONDS);
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 500 "));

        _server.stop();

        RoleRefHandler roleref = new RoleRefHandler();
        roleref.setHandler(_security.getHandler());
        _security.setHandler(roleref);
        roleref.setHandler(check);

        _server.start();

        response = _connector.getResponses("GET /ctx/auth/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user2:password") + "\r\n" +
                "\r\n", 100000, TimeUnit.MILLISECONDS);
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
    }

    @Test
    public void testDeferredBasic() throws Exception
    {
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n"+
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        Assert.assertThat(response, Matchers.containsString("user=null"));

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n"+
                "Authorization: Basic " + B64Code.encode("admin:wrong") + "\r\n" +
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        Assert.assertThat(response, Matchers.containsString("user=null"));

        response = _connector.getResponses("GET /ctx/noauth/info HTTP/1.0\r\n"+
                "Authorization: Basic " + B64Code.encode("admin:password") + "\r\n" +
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 OK"));
        Assert.assertThat(response, Matchers.containsString("user=admin"));
    }

    @Test
    public void testRelaxedMethod() throws Exception
    {
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/forbid/somethig HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));

        response = _connector.getResponses("POST /ctx/forbid/post HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));

        response = _connector.getResponses("GET /ctx/forbid/post HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));  // This is so stupid, but it is the S P E C
    }

    private static final String[] INVALID_HTTP_METHOD_NAMES = {
        "*",
        "  ",
        "\t",
        "bogus name"
    };

    @Test
    public void testSetInvalidHttpMethod()
    {
        for (String name : INVALID_HTTP_METHOD_NAMES)
        {
            ConstraintMapping mapping = new ConstraintMapping();
            try
            {
                mapping.setMethod(name);
                Assert.fail("Expected IllegalArgumentException for http-method [" + name + "]");
            }
            catch (IllegalArgumentException expected)
            {
                // expected
            }
        }
    }

    @Test
    public void testSetInvalidHttpMethodOmission()
    {
        for (String name : INVALID_HTTP_METHOD_NAMES)
        {
            ConstraintMapping mapping = new ConstraintMapping();
            try
            {
                mapping.setMethodOmissions(new String[]{name});
                Assert.fail("Expected IllegalArgumentException for http-method-omission [" + name + "]");
            }
            catch (IllegalArgumentException expected)
            {
                // expected
            }
        }
    }

    @Test
    public void testSetHttpMethodOmissionWithNullEntries()
    {
        ConstraintMapping mapping = new ConstraintMapping();
        String[] names = new String[]{"GET", null, "POST"};
        try
        {
            mapping.setMethodOmissions(names);
            Assert.fail("Expected IllegalArgumentException for null http-method-omission entry");
        }
        catch (IllegalArgumentException expected)
        {
            // expected
        }
    }

    /**
     * Replication of Constraint combination from
     * <a href="https://jakarta.ee/specifications/servlet/5.0/jakarta-servlet-spec-5.0#combining-constraints">Jakarta Servlet Spec 13.8.1 : Combining Constraints</a>.
     * @throws Exception if test fails
     */
    @Test
    public void testServletSpecCombinedConstraintsExamples() throws Exception
    {
        // httpMethod, requestPath, expectedIsChecked, expectedForbidden, expectedRoles, expectedConfidential
        Object[][] cases = {
            // Test the Table 13-4 "Security Constraint Table" url-pattern of "/*"
            {"PUT", "/foo", true, true, new String[]{}, false},
            {"GET", "/foo", false, false, null, null},
            {"POST", "/foo", false, false, null, null},
            // Test the Table 13-4 "Security Constraint Table" url-pattern of "/acme/wholesale/*"
            {"PUT", "/acme/wholesale/foo", true, false, new String[]{"SALESCLERK"}, false},
            {"GET", "/acme/wholesale/foo", true, false, new String[]{"CONTRACTOR", "SALESCLERK"}, false},
            {"POST", "/acme/wholesale/foo", true, false, new String[]{"CONTRACTOR"}, true},
            // Test the Table 13-4 "Security Constraint Table" url-pattern of "/acme/retail/*"
            {"PUT", "/acme/retail/foo", true, true, new String[]{}, false},
            {"GET", "/acme/retail/foo", true, false, new String[]{"CONTRACTOR", "HOMEOWNER"}, false},
            {"POST", "/acme/retail/foo", true, false, new String[]{"CONTRACTOR", "HOMEOWNER"}, false}
        };

        List<ConstraintMapping> mappings = new ArrayList<>();

        // Note: the path spec `/*` is known to produce the "has uncovered HTTP methods" warning, do not try to fix by changing these constraints.

        /*
        <security-constraint>
          <web-resource-collection>
            <web-resource-name>precluded methods</web-resource-name>
            <url-pattern>/*</url-pattern>
            <url-pattern>/acme/wholesale/*</url-pattern>
            <url-pattern>/acme/retail/*</url-pattern>
            <http-method-omission>GET</http-method-omission>
            <http-method-omission>POST</http-method-omission>
          </web-resource-collection>
          <auth-constraint/>
        </security-constraint>
         */
        Constraint forbidConstraint = new Constraint();
        forbidConstraint.setAuthenticate(true);
        forbidConstraint.setName("forbidden");
        for (String pathSpec : Arrays.asList("/*", "/acme/wholesale/*", "/acme/retail/*"))
        {
            ConstraintMapping mapping = new ConstraintMapping();
            mapping.setPathSpec(pathSpec);
            mapping.setMethodOmissions(new String[]{"GET", "POST"});
            mapping.setConstraint(forbidConstraint);
            mappings.add(mapping);
        }

        /*
        <security-constraint>
          <web-resource-collection>
            <web-resource-name>wholesale</web-resource-name>
            <url-pattern>/acme/wholesale/*</url-pattern>
            <http-method>GET</http-method>
            <http-method>PUT</http-method>
          </web-resource-collection>
          <auth-constraint>
            <role-name>SALESCLERK</role-name>
          </auth-constraint>
        </security-constraint>
         */
        Constraint wholesaleConstraint = new Constraint();
        wholesaleConstraint.setAuthenticate(true);
        wholesaleConstraint.setRoles(new String[]{"SALESCLERK"});
        for (String wholesaleMethod : Arrays.asList("GET", "PUT"))
        {
            ConstraintMapping mapping = new ConstraintMapping();
            mapping.setPathSpec("/acme/wholesale/*");
            mapping.setMethod(wholesaleMethod);
            mapping.setConstraint(wholesaleConstraint);
            mappings.add(mapping);
        }

        /*
        <security-constraint>
          <web-resource-collection>
            <web-resource-name>wholesale 2</web-resource-name>
            <url-pattern>/acme/wholesale/*</url-pattern>
            <http-method>GET</http-method>
            <http-method>POST</http-method>
          </web-resource-collection>
          <auth-constraint>
            <role-name>CONTRACTOR</role-name>
          </auth-constraint>
          <user-data-constraint>
            <transport-guarantee>CONFIDENTIAL</transport-guarantee>
          </user-data-constraint>
        </security-constraint>
         */
        Constraint wholesale2Constraint = new Constraint();
        wholesale2Constraint.setAuthenticate(true);
        wholesale2Constraint.setRoles(new String[]{"CONTRACTOR"});
        wholesale2Constraint.setDataConstraint(Constraint.DC_CONFIDENTIAL);
        for (String wholesale2Method : Arrays.asList("GET", "POST"))
        {
            ConstraintMapping mapping = new ConstraintMapping();
            mapping.setPathSpec("/acme/wholesale/*");
            mapping.setMethod(wholesale2Method);
            mapping.setConstraint(wholesale2Constraint);
            mappings.add(mapping);
        }

        /*
        <security-constraint>
          <web-resource-collection>
            <web-resource-name>retail</web-resource-name>
            <url-pattern>/acme/retail/*</url-pattern>
            <http-method>GET</http-method>
            <http-method>POST</http-method>
          </web-resource-collection>

          <auth-constraint>
            <role-name>CONTRACTOR</role-name>
            <role-name>HOMEOWNER</role-name>
          </auth-constraint>
        </security-constraint>
         */
        Constraint retailConstraint = new Constraint();
        retailConstraint.setAuthenticate(true);
        retailConstraint.setRoles(new String[]{"CONTRACTOR", "HOMEOWNER"});
        for (String retailMethod : Arrays.asList("GET", "POST"))
        {
            ConstraintMapping mapping = new ConstraintMapping();
            mapping.setPathSpec("/acme/retail/*");
            mapping.setMethod(retailMethod);
            mapping.setConstraint(retailConstraint);
            mappings.add(mapping);
        }

        Set<String> knownRoles = new HashSet<>(Arrays.asList("SALESCLERK", "CONTRACTOR", "HOMEOWNER"));
        _security.setConstraintMappings(mappings, knownRoles);
        _server.start();

        for (Object[] c : cases)
        {
            String httpMethod = (String)c[0];
            String requestPath = (String)c[1];
            boolean expectedIsChecked = (Boolean)c[2];
            boolean expectedForbidden = (Boolean)c[3];
            String[] expectedRoles = (String[])c[4];
            Boolean expectedConfidential = (Boolean)c[5];

            RoleInfo roleInfo = _security.prepareConstraintInfo(requestPath, httpMethod);
            Assert.assertEquals(String.format("%s %s roleInfo isChecked", httpMethod, requestPath), expectedIsChecked, roleInfo.isChecked());
            if (roleInfo.isChecked())
            {
                Assert.assertEquals(String.format("%s %s forbidden", httpMethod, requestPath), expectedForbidden, roleInfo.isForbidden());
                Assert.assertEquals(String.format("%s %s roles", httpMethod, requestPath), new HashSet<>(Arrays.asList(expectedRoles)), roleInfo.getRoles());
                Assert.assertEquals(String.format("%s %s user data constraint", httpMethod, requestPath),
                    expectedConfidential, roleInfo.getUserDataConstraint() == UserDataConstraint.Confidential);
            }
        }
    }

    private static final Object[][] SINGLE_METHOD_OMISSION_CASES = {
        // Try some RFC9110 standardized method declarations
        {"GET", "GET", "/test/foo", false},
        {"GET", "PUT", "/test/foo", true},
        {"GET", "POST", "/test/foo", true},
        {"GET", "DELETE", "/test/foo", true},
        // Try some WebDav methods
        {"PATCH", "PATCH", "/test/foo", false},
        {"PATCH", "PROPPATCH", "/test/foo", true},
        {"PATCH", "ORDERPATCH", "/test/foo", true},
        {"PATCH", "PROPFIND", "/test/foo", true},
        {"PATCH", "MKCOL", "/test/foo", true},
        {"MKCOL", "MKCOL", "/test/foo", false},
        {"PROPPATCH", "PATCH", "/test/foo", true},
        {"PROPPATCH", "ORDERPATCH", "/test/foo", true},
        {"PROPFIND", "PROPFIND", "/test/foo", false},
        // Try some non-standard method declarations
        {"CorpQuery", "CorpQuery", "/test/foo", false},
        {"CorpQuery", "GET", "/test/foo", true},
        {"CorpQuery", "POST", "/test/foo", true}
    };

    /**
     * Stop the current server and create a fresh one (with a fresh security handler).
     * @throws Exception if the server cannot be stopped
     */
    private void resetServer() throws Exception
    {
        stopServer();
        startServer();
    }

    /**
     * Tests forbidden http-method-omission
     * @throws Exception if test fails
     */
    @Test
    public void testSingleForbiddenMethodOmissionConstraint() throws Exception
    {
        for (Object[] c : SINGLE_METHOD_OMISSION_CASES)
        {
            String httpMethodOmission = (String)c[0];
            String requestHttpMethod = (String)c[1];
            String requestPath = (String)c[2];
            boolean expectedForbidden = (Boolean)c[3];

            resetServer();
            Constraint forbidConstraint = new Constraint();
            forbidConstraint.setAuthenticate(true);
            forbidConstraint.setName("forbid");
            ConstraintMapping forbiddenMapping = new ConstraintMapping();
            forbiddenMapping.setPathSpec("/test/*");
            forbiddenMapping.setMethodOmissions(new String[]{httpMethodOmission});
            forbiddenMapping.setConstraint(forbidConstraint);
            _security.setConstraintMappings(Collections.singletonList(forbiddenMapping));
            _server.start();

            RoleInfo roleInfo = _security.prepareConstraintInfo(requestPath, requestHttpMethod);
            boolean constraintIsChecked = expectedForbidden && !httpMethodOmission.equalsIgnoreCase(requestHttpMethod);
            Assert.assertEquals(String.format("omit %s: %s %s roleInfo isChecked", httpMethodOmission, requestHttpMethod, requestPath), constraintIsChecked, roleInfo.isChecked());
            if (roleInfo.isChecked())
            {
                Assert.assertEquals(String.format("omit %s: %s %s forbidden", httpMethodOmission, requestHttpMethod, requestPath), expectedForbidden, roleInfo.isForbidden());
            }
        }
    }

    /**
     * Tests allowed http-method-omission
     * @throws Exception if test fails
     */
    @Test
    public void testSingleAllowedMethodOmissionConstraint() throws Exception
    {
        for (Object[] c : SINGLE_METHOD_OMISSION_CASES)
        {
            String httpMethodOmission = (String)c[0];
            String requestHttpMethod = (String)c[1];
            String requestPath = (String)c[2];
            boolean expectAllowed = (Boolean)c[3];

            resetServer();
            Constraint allowConstraint = new Constraint();
            allowConstraint.setAuthenticate(false);
            allowConstraint.setName("allowed");
            ConstraintMapping allowedMapping = new ConstraintMapping();
            allowedMapping.setPathSpec("/test/*");
            allowedMapping.setMethodOmissions(new String[]{httpMethodOmission});
            allowedMapping.setConstraint(allowConstraint);
            _security.setConstraintMappings(Collections.singletonList(allowedMapping));
            _server.start();

            RoleInfo roleInfo = _security.prepareConstraintInfo(requestPath, requestHttpMethod);
            boolean constraintIsChecked = !expectAllowed && !httpMethodOmission.equalsIgnoreCase(requestHttpMethod);
            Assert.assertEquals(String.format("omit %s: %s %s roleInfo isChecked", httpMethodOmission, requestHttpMethod, requestPath), constraintIsChecked, roleInfo.isChecked());
            if (roleInfo.isChecked())
            {
                Assert.assertEquals(String.format("omit %s: %s %s allowed", httpMethodOmission, requestHttpMethod, requestPath), !expectAllowed, roleInfo.isForbidden());
            }
        }
    }

    private static final Object[][] COMBINED_ALLOWED_FORBIDDEN_METHOD_OMISSION_CASES = {
        // Neither constraint covers GET
        {"GET", "/test/foo", false},
        // The forbidden constraint wins
        {"PUT", "/test/foo", true},
        {"POST", "/test/foo", true},
        {"DELETE", "/test/foo", true}
    };

    private void assertCombinedAllowedForbiddenMethodOmissionConstraints(boolean forbiddenFirst) throws Exception
    {
        // Note: these two constraints are known to produce the "has uncovered HTTP methods" warning, do not try to fix by changing these constraints.
        Constraint forbidConstraint = new Constraint();
        forbidConstraint.setAuthenticate(true);
        forbidConstraint.setName("forbidden");
        ConstraintMapping forbiddenMapping = new ConstraintMapping();
        forbiddenMapping.setPathSpec("/test/*");
        forbiddenMapping.setMethodOmissions(new String[]{"GET"});
        forbiddenMapping.setConstraint(forbidConstraint);

        Constraint allowConstraint = new Constraint();
        allowConstraint.setAuthenticate(false);
        allowConstraint.setName("allowed");
        ConstraintMapping allowedMapping = new ConstraintMapping();
        allowedMapping.setPathSpec("/test/*");
        allowedMapping.setMethodOmissions(new String[]{"GET"});
        allowedMapping.setConstraint(allowConstraint);

        if (forbiddenFirst)
            _security.setConstraintMappings(Arrays.asList(forbiddenMapping, allowedMapping));
        else
            _security.setConstraintMappings(Arrays.asList(allowedMapping, forbiddenMapping));
        _server.start();

        for (Object[] c : COMBINED_ALLOWED_FORBIDDEN_METHOD_OMISSION_CASES)
        {
            String httpMethod = (String)c[0];
            String requestPath = (String)c[1];
            boolean expectedForbidden = (Boolean)c[2];

            RoleInfo roleInfo = _security.prepareConstraintInfo(requestPath, httpMethod);
            boolean constraintIsChecked = expectedForbidden && !"GET".equalsIgnoreCase(httpMethod);
            Assert.assertEquals(String.format("%s %s roleInfo isChecked", httpMethod, requestPath), constraintIsChecked, roleInfo.isChecked());
            if (roleInfo.isChecked())
            {
                Assert.assertEquals(String.format("%s %s forbidden", httpMethod, requestPath), expectedForbidden, roleInfo.isForbidden());
            }
        }
    }

    /**
     * Test of two constraints that have the same path, same http-method-omission, no roles, but different auth-constraint settings.
     * @throws Exception if test fails
     */
    @Test
    public void testCombinedAllowedForbiddenMethodOmissionConstraints() throws Exception
    {
        // This is the reverse order from testCombinedForbiddenAllowedMethodOmissionConstraints
        assertCombinedAllowedForbiddenMethodOmissionConstraints(false);
    }

    /**
     * Test of two constraints that have the same path, same http-method-omission, no roles, but different auth-constraint settings.
     * @throws Exception if test fails
     */
    @Test
    public void testCombinedForbiddenAllowedMethodOmissionConstraints() throws Exception
    {
        // This is the reverse order from testCombinedAllowedForbiddenMethodOmissionConstraints
        assertCombinedAllowedForbiddenMethodOmissionConstraints(true);
    }

    /**
     * Request methods that are a substring of an http-method-omission must not be treated as omitted
     * (ie they must still be covered by the constraint).
     * @throws Exception if test fails
     */
    @Test
    public void testMethodOmissionSubstringBypass() throws Exception
    {
        String[][] cases = {
            // omitted method, attacker method that is a substring of the omission key
            {"PROPPATCH", "PATCH"},
            {"UNLOCK", "LOCK"},
            {"UNBIND", "BIND"},
            {"REBIND", "BIND"},
            {"UNLINK", "LINK"},
            {"GET", "ET"},
            {"GET", "omission"},
            {"GET", "T.omission"}
        };

        for (String[] c : cases)
        {
            String omittedMethod = c[0];
            String attackMethod = c[1];

            resetServer();
            Constraint adminConstraint = new Constraint();
            adminConstraint.setAuthenticate(true);
            adminConstraint.setName("admin omission");
            adminConstraint.setRoles(new String[]{"administrator"});
            ConstraintMapping mapping = new ConstraintMapping();
            mapping.setPathSpec("/secure/*");
            mapping.setMethodOmissions(new String[]{omittedMethod});
            mapping.setConstraint(adminConstraint);
            _security.addConstraintMapping(mapping);
            _security.setAuthenticator(new BasicAuthenticator());
            _server.start();

            String response;
            // The omitted method is not covered by the constraint
            response = _connector.getResponses(omittedMethod + " /ctx/secure/info HTTP/1.0\r\n\r\n");
            Assert.assertThat(omittedMethod, response, Matchers.startsWith("HTTP/1.1 200 "));

            // Any other method is covered by the constraint
            response = _connector.getResponses("POST /ctx/secure/info HTTP/1.0\r\n\r\n");
            Assert.assertThat(omittedMethod, response, Matchers.startsWith("HTTP/1.1 401 "));

            // A method that is a substring of the omission must also be covered by the constraint
            response = _connector.getResponses(attackMethod + " /ctx/secure/info HTTP/1.0\r\n\r\n");
            Assert.assertThat(omittedMethod + " vs " + attackMethod, response, Matchers.startsWith("HTTP/1.1 401 "));

            response = _connector.getResponses(attackMethod + " /ctx/secure/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("admin:password") + "\r\n" +
                "\r\n");
            Assert.assertThat(omittedMethod + " vs " + attackMethod, response, Matchers.startsWith("HTTP/1.1 200 "));
            Assert.assertThat(omittedMethod + " vs " + attackMethod, response, Matchers.containsString("user=admin"));
        }
    }

    @Test
    public void testMultipleMethodOmissionSubstringBypass() throws Exception
    {
        Constraint adminConstraint = new Constraint();
        adminConstraint.setAuthenticate(true);
        adminConstraint.setName("admin omission");
        adminConstraint.setRoles(new String[]{"administrator"});
        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/secure/*");
        mapping.setMethodOmissions(new String[]{"GET", "PROPPATCH"});
        mapping.setConstraint(adminConstraint);
        _security.addConstraintMapping(mapping);
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/secure/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));
        response = _connector.getResponses("PROPPATCH /ctx/secure/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));

        for (String method : Arrays.asList("PATCH", "GET.PROPPATCH", "T.PROP", "POST", "PUT"))
        {
            response = _connector.getResponses(method + " /ctx/secure/info HTTP/1.0\r\n\r\n");
            Assert.assertThat(method, response, Matchers.startsWith("HTTP/1.1 401 "));
        }
    }

    /**
     * A request method spelled like an internal constraint mapping key ("*" or "&lt;method&gt;.omission")
     * must not short-cut the combination of the http-method-omission constraints.
     * @throws Exception if test fails
     */
    @Test
    public void testRequestMethodNamedLikeAllMethodsKey() throws Exception
    {
        Constraint relaxConstraint = new Constraint();
        relaxConstraint.setAuthenticate(false);
        relaxConstraint.setName("relax");
        ConstraintMapping allMethods = new ConstraintMapping();
        allMethods.setPathSpec("/star/*");
        allMethods.setConstraint(relaxConstraint);

        Constraint adminConstraint = new Constraint();
        adminConstraint.setAuthenticate(true);
        adminConstraint.setName("admin");
        adminConstraint.setRoles(new String[]{"administrator"});
        ConstraintMapping adminOmitGet = new ConstraintMapping();
        adminOmitGet.setPathSpec("/star/*");
        adminOmitGet.setMethodOmissions(new String[]{"GET"});
        adminOmitGet.setConstraint(adminConstraint);

        _security.addConstraintMapping(allMethods);
        _security.addConstraintMapping(adminOmitGet);
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/star/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));

        response = _connector.getResponses("PUT /ctx/star/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 "));

        response = _connector.getResponses("* /ctx/star/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 "));

        response = _connector.getResponses("* /ctx/star/info HTTP/1.0\r\n" +
            "Authorization: Basic " + B64Code.encode("admin:password") + "\r\n" +
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));
        Assert.assertThat(response, Matchers.containsString("user=admin"));
    }

    @Test
    public void testRequestMethodNamedLikeMethodOmissionKey() throws Exception
    {
        Constraint adminConstraint = new Constraint();
        adminConstraint.setAuthenticate(true);
        adminConstraint.setName("admin");
        adminConstraint.setRoles(new String[]{"administrator"});
        ConstraintMapping allMethods = new ConstraintMapping();
        allMethods.setPathSpec("/dotomit/*");
        allMethods.setConstraint(adminConstraint);

        Constraint relaxConstraint = new Constraint();
        relaxConstraint.setAuthenticate(false);
        relaxConstraint.setName("relax");
        ConstraintMapping relaxOmitGet = new ConstraintMapping();
        relaxOmitGet.setPathSpec("/dotomit/*");
        relaxOmitGet.setMethodOmissions(new String[]{"GET"});
        relaxOmitGet.setConstraint(relaxConstraint);

        _security.addConstraintMapping(allMethods);
        _security.addConstraintMapping(relaxOmitGet);
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;
        response = _connector.getResponses("PUT /ctx/dotomit/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 "));

        response = _connector.getResponses("GET.omission /ctx/dotomit/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 401 "));
    }

    private void assertDuplicateMethodOmissionConstraintsCombined(boolean forbiddenFirst) throws Exception
    {
        Constraint forbidConstraint = new Constraint();
        forbidConstraint.setAuthenticate(true);
        forbidConstraint.setName("forbid");
        ConstraintMapping forbidOmitGet = new ConstraintMapping();
        forbidOmitGet.setPathSpec("/dup/*");
        forbidOmitGet.setMethodOmissions(new String[]{"GET"});
        forbidOmitGet.setConstraint(forbidConstraint);

        Constraint relaxConstraint = new Constraint();
        relaxConstraint.setAuthenticate(false);
        relaxConstraint.setName("relax");
        ConstraintMapping relaxOmitGet = new ConstraintMapping();
        relaxOmitGet.setPathSpec("/dup/*");
        relaxOmitGet.setMethodOmissions(new String[]{"GET"});
        relaxOmitGet.setConstraint(relaxConstraint);

        if (forbiddenFirst)
        {
            _security.addConstraintMapping(forbidOmitGet);
            _security.addConstraintMapping(relaxOmitGet);
        }
        else
        {
            _security.addConstraintMapping(relaxOmitGet);
            _security.addConstraintMapping(forbidOmitGet);
        }
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        String response;
        response = _connector.getResponses("GET /ctx/dup/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));

        response = _connector.getResponses("POST /ctx/dup/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));

        response = _connector.getResponses("POST /ctx/dup/info HTTP/1.0\r\n" +
            "Authorization: Basic " + B64Code.encode("admin:password") + "\r\n" +
            "\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));
    }

    /**
     * Two constraints with the same path and the same http-method-omission must be combined,
     * regardless of their declaration order, so the forbidden constraint is not overridden.
     * @throws Exception if test fails
     */
    @Test
    public void testDuplicateMethodOmissionConstraintsCombinedForbiddenFirst() throws Exception
    {
        assertDuplicateMethodOmissionConstraintsCombined(true);
    }

    @Test
    public void testDuplicateMethodOmissionConstraintsCombinedForbiddenLast() throws Exception
    {
        assertDuplicateMethodOmissionConstraintsCombined(false);
    }

    @Test
    public void testDuplicateMethodOmissionConstraintsCombinedWhenStarted() throws Exception
    {
        _security.setAuthenticator(new BasicAuthenticator());
        _server.start();

        Constraint forbidConstraint = new Constraint();
        forbidConstraint.setAuthenticate(true);
        forbidConstraint.setName("forbid");
        ConstraintMapping forbidOmitGet = new ConstraintMapping();
        forbidOmitGet.setPathSpec("/dup/*");
        forbidOmitGet.setMethodOmissions(new String[]{"GET"});
        forbidOmitGet.setConstraint(forbidConstraint);
        _security.addConstraintMapping(forbidOmitGet);

        String response;
        response = _connector.getResponses("POST /ctx/dup/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));

        Constraint relaxConstraint = new Constraint();
        relaxConstraint.setAuthenticate(false);
        relaxConstraint.setName("relax");
        ConstraintMapping relaxOmitGet = new ConstraintMapping();
        relaxOmitGet.setPathSpec("/dup/*");
        relaxOmitGet.setMethodOmissions(new String[]{"GET"});
        relaxOmitGet.setConstraint(relaxConstraint);
        _security.addConstraintMapping(relaxOmitGet);

        response = _connector.getResponses("POST /ctx/dup/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 403 "));
        response = _connector.getResponses("GET /ctx/dup/info HTTP/1.0\r\n\r\n");
        Assert.assertThat(response, Matchers.startsWith("HTTP/1.1 200 "));
    }

    /**
     * Duplicate http-method-omission constraints (forbidden one first) that are also combined with
     * a constraint covering all methods of the same path must still result in the request being forbidden.
     * @throws Exception if test fails
     */
    @Test
    public void testDuplicateMethodOmissionConstraintsCombinedWithAllMethodsConstraint() throws Exception
    {
        for (boolean forbiddenFirst : new boolean[]{true, false})
        {
            resetServer();
            Constraint userConstraint = new Constraint();
            userConstraint.setAuthenticate(true);
            userConstraint.setName("user");
            userConstraint.setRoles(new String[]{"user"});
            ConstraintMapping allMethods = new ConstraintMapping();
            allMethods.setPathSpec("/dupall/*");
            allMethods.setConstraint(userConstraint);

            Constraint forbidConstraint = new Constraint();
            forbidConstraint.setAuthenticate(true);
            forbidConstraint.setName("forbid");
            ConstraintMapping forbidOmitGet = new ConstraintMapping();
            forbidOmitGet.setPathSpec("/dupall/*");
            forbidOmitGet.setMethodOmissions(new String[]{"GET"});
            forbidOmitGet.setConstraint(forbidConstraint);

            Constraint relaxConstraint = new Constraint();
            relaxConstraint.setAuthenticate(false);
            relaxConstraint.setName("relax");
            ConstraintMapping relaxOmitGet = new ConstraintMapping();
            relaxOmitGet.setPathSpec("/dupall/*");
            relaxOmitGet.setMethodOmissions(new String[]{"GET"});
            relaxOmitGet.setConstraint(relaxConstraint);

            _security.addConstraintMapping(allMethods);
            if (forbiddenFirst)
            {
                _security.addConstraintMapping(forbidOmitGet);
                _security.addConstraintMapping(relaxOmitGet);
            }
            else
            {
                _security.addConstraintMapping(relaxOmitGet);
                _security.addConstraintMapping(forbidOmitGet);
            }
            _security.setAuthenticator(new BasicAuthenticator());
            _server.start();

            String response;
            response = _connector.getResponses("GET /ctx/dupall/info HTTP/1.0\r\n\r\n");
            Assert.assertThat("forbiddenFirst=" + forbiddenFirst, response, Matchers.startsWith("HTTP/1.1 401 "));

            response = _connector.getResponses("GET /ctx/dupall/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user:password") + "\r\n" +
                "\r\n");
            Assert.assertThat("forbiddenFirst=" + forbiddenFirst, response, Matchers.startsWith("HTTP/1.1 200 "));

            response = _connector.getResponses("POST /ctx/dupall/info HTTP/1.0\r\n\r\n");
            Assert.assertThat("forbiddenFirst=" + forbiddenFirst, response, Matchers.startsWith("HTTP/1.1 403 "));

            response = _connector.getResponses("POST /ctx/dupall/info HTTP/1.0\r\n" +
                "Authorization: Basic " + B64Code.encode("user:password") + "\r\n" +
                "\r\n");
            Assert.assertThat("forbiddenFirst=" + forbiddenFirst, response, Matchers.startsWith("HTTP/1.1 403 "));
        }
    }
    private class RequestHandler extends AbstractHandler
    {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response ) throws IOException, ServletException
        {
            baseRequest.setHandled(true);
            if (request.getAuthType()==null || "user".equals(request.getRemoteUser()) || request.isUserInRole("user") || request.isUserInRole("foo"))
            {
                response.setStatus(200);
                response.setContentType("text/plain; charset=UTF-8");
                response.getWriter().println("URI="+request.getRequestURI());
                String user = request.getRemoteUser();
                response.getWriter().println("user="+user);
                if (request.getParameter("test_parameter")!=null)
                    response.getWriter().println(request.getParameter("test_parameter"));
            }
            else
                response.sendError(500);
        }
    }

    private class RoleRefHandler extends HandlerWrapper
    {
        /* ------------------------------------------------------------ */
        /**
         * @see org.eclipse.jetty.server.handler.HandlerWrapper#handle(java.lang.String, Request, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
         */
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
        {
            UserIdentity.Scope old = ((Request) request).getUserIdentityScope();

            UserIdentity.Scope scope = new UserIdentity.Scope()
            {
                @Override
                public String getContextPath()
                {
                    return "/";
                }

                @Override
                public String getName()
                {
                    return "someServlet";
                }

                @Override
                public Map<String, String> getRoleRefMap()
                {
                    Map<String, String> map = new HashMap<>();
                    map.put("untranslated", "user");
                    return map;
                }
            };

            ((Request)request).setUserIdentityScope(scope);

            try
            {
                super.handle(target,baseRequest,request, response);
            }
            finally
            {
                ((Request)request).setUserIdentityScope(old);
            }
        }
    }

    private class RoleCheckHandler extends AbstractHandler
    {
        @Override
        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response ) throws IOException, ServletException
        {
            ((Request) request).setHandled(true);
            if (request.getAuthType()==null || "user".equals(request.getRemoteUser()) || request.isUserInRole("untranslated"))
                response.setStatus(200);
            else
                response.sendError(500);
        }
    }
}
