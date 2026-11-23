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

import java.util.Arrays;

import org.eclipse.jetty.util.StringUtil;
import org.eclipse.jetty.util.security.Constraint;

public class ConstraintMapping
{
    String _method;
    String[] _methodOmissions;

    String _pathSpec;

    Constraint _constraint;

    /* ------------------------------------------------------------ */
    /**
     * @return Returns the constraint.
     */
    public Constraint getConstraint()
    {
        return _constraint;
    }

    /* ------------------------------------------------------------ */
    /**
     * @param constraint The constraint to set.
     */
    public void setConstraint(Constraint constraint)
    {
        this._constraint = constraint;
    }

    /* ------------------------------------------------------------ */
    /**
     * @return Returns the method.
     */
    public String getMethod()
    {
        return _method;
    }

    /* ------------------------------------------------------------ */
    /**
     * @param method The method to set.
     */
    public void setMethod(String method)
    {
        if (method != null)
            checkHttpMethodName(method, "Servlet Constraint HTTP Method");

        this._method = method;
    }

    /* ------------------------------------------------------------ */
    /**
     * @return Returns the pathSpec.
     */
    public String getPathSpec()
    {
        return _pathSpec;
    }

    /* ------------------------------------------------------------ */
    /**
     * @param pathSpec The pathSpec to set.
     */
    public void setPathSpec(String pathSpec)
    {
        this._pathSpec = pathSpec;
    }
    
    /* ------------------------------------------------------------ */
    /**
     * @param omissions The http-method-omission
     */
    public void setMethodOmissions(String[] omissions)
    {
        if (omissions != null)
        {
            for (String omission : omissions)
                checkHttpMethodName(omission, "Servlet Constraint HTTP Method Omission");
        }

        _methodOmissions = omissions;
    }
    
    /* ------------------------------------------------------------ */
    public String[] getMethodOmissions()
    {
        return _methodOmissions;
    }

    public boolean hasMethodOmissions()
    {
        return _methodOmissions != null && _methodOmissions.length > 0;
    }

    private void checkHttpMethodName(String methodName, String msg)
    {
        if (StringUtil.isBlank(methodName))
            throw new IllegalArgumentException("Blank HTTP Method Name: " + msg);
        if ("*".equals(methodName))
            throw new IllegalArgumentException("Invalid HTTP Method Name '*': " + msg);
        requireValidRFC2616Token(methodName, msg);
    }

    /**
     * Per RFC2616: Section 2.2, a token follows these syntax rules
     * <pre>
     *  token          = 1*&lt;any CHAR except CTLs or separators&gt;
     *  CHAR           = &lt;any US-ASCII character (octets 0 - 127)&gt;
     *  CTL            = &lt;any US-ASCII control character
     *                   (octets 0 - 31) and DEL (127)&gt;
     *  separators     = "(" | ")" | "&lt;" | "&gt;" | "@"
     *                 | "," | ";" | ":" | "\" | &lt;"&gt;
     *                 | "/" | "[" | "]" | "?" | "="
     *                 | "{" | "}" | SP | HT
     * </pre>
     *
     * @param value the value to test
     * @param msg the message to be prefixed if an {@link IllegalArgumentException} is thrown.
     * @throws IllegalArgumentException if the value is invalid per spec
     */
    private static void requireValidRFC2616Token(String value, String msg)
    {
        if (value == null)
            return;

        int valueLen = value.length();
        if (valueLen == 0)
            return;

        for (int i = 0; i < valueLen; i++)
        {
            char c = value.charAt(i);

            // 0x00 - 0x1F are low order control characters
            // 0x7F is the DEL control character
            if ((c <= 0x1F) || (c == 0x7F))
                throw new IllegalArgumentException(msg + ": RFC2616 tokens may not contain control characters");
            if (c == '(' || c == ')' || c == '<' || c == '>' || c == '@'
                || c == ',' || c == ';' || c == ':' || c == '\\' || c == '"'
                || c == '/' || c == '[' || c == ']' || c == '?' || c == '='
                || c == '{' || c == '}' || c == ' ')
            {
                throw new IllegalArgumentException(msg + ": RFC2616 tokens may not contain separator character: [" + c + "]");
            }
            if (c >= 0x80)
                throw new IllegalArgumentException(msg + ": RFC2616 tokens characters restricted to US-ASCII: 0x" + Integer.toHexString(c));
        }
    }

    @Override
    public String toString()
    {
        return String.format("%s@%x{method=%s,omissions=%s,pathSpec=%s -> %s}",
            getClass().getSimpleName(),
            hashCode(),
            _method,
            _methodOmissions == null ? null : Arrays.asList(_methodOmissions),
            _pathSpec,
            _constraint);
    }
}
