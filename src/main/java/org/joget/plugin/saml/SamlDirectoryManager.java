package org.joget.plugin.saml;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.directory.model.service.DirectoryManagerAuthenticator;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * SAML SP implementation adapted from https://github.com/onelogin/java-saml/tree/v1.1.2
 */
public class SamlDirectoryManager extends SecureDirectoryManager {

    @Override
    public String getName() {
        return "SAML Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager with support for SAML 2.0";
    }

    @Override
    public String getVersion() {
        return "6.0.2";
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        return super.getDirectoryManagerImpl(properties);
    }
        
    @Override
    public String getPropertyOptions() {
        UserSecurityFactory f = (UserSecurityFactory) new SecureDirectoryManagerImpl(null);
        String usJson = f.getUserSecurity().getPropertyOptions();
        usJson = usJson.replaceAll("\\n", "\\\\n");

        String addOnJson = "";
        if (SecureDirectoryManagerImpl.NUM_OF_DM > 1) {
            for (int i = 2; i <= SecureDirectoryManagerImpl.NUM_OF_DM; i++) {
                addOnJson += ",{\nname : 'dm" + i + "',\n label : '@@app.edm.label.addon@@',\n type : 'elementselect',\n";
                addOnJson += "options_ajax : '[CONTEXT_PATH]/web/json/plugin/org.joget.plugin.directory.SecureDirectoryManager/service',\n";
                addOnJson += "url : '[CONTEXT_PATH]/web/property/json/getPropertyOptions'\n}";
            }
        }

        HttpServletRequest request = WorkflowUtil.getHttpServletRequest();
        String acsUrl = request.getScheme()+ "://" + request.getServerName();
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            acsUrl += ":" + request.getServerPort();
        }
        acsUrl += request.getContextPath() + "/web/json/plugin/org.joget.plugin.saml.SamlDirectoryManager/service";
        String entityId = acsUrl;
        
        String json = AppUtil.readPluginResource(getClass().getName(), "/properties/app/samlDirectoryManager.json", new String[]{entityId, acsUrl, usJson, addOnJson}, true, null);
        return json;
    }

    @Override
    public String getLabel() {
        return "SAML Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        String action = request.getParameter("action");
        if ("dmOptions".equals(action)) {
            super.webService(request, response);
        } else if (request.getParameter("SAMLResponse") != null) {
            doLogin(request, response);
        } else {
            response.sendError(HttpServletResponse.SC_NO_CONTENT);
        }

    }
            
    void doLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {

            // read from properties
            DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl)AppUtil.getApplicationContext().getBean("directoryManager");
            SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl)dm.getDirectoryManagerImpl();
            String certificate = dmImpl.getPropertyString("certificate");
            boolean userProvisioningEnabled = Boolean.parseBoolean(dmImpl.getPropertyString("userProvisioning"));
            String attrEmail = dmImpl.getPropertyString("attrEmail");
            String attrFirstName = dmImpl.getPropertyString("attrFirstName");
            String attrLastName = dmImpl.getPropertyString("attrLastName");
                        
            if (certificate == null || certificate.isEmpty()) {
                throw new CertificateException("IDP certificate is missing");
            }

            AccountSettings accountSettings = new AccountSettings();
            accountSettings.setCertificate(certificate);
            SamlResponse samlResponse = new SamlResponse(accountSettings);
            samlResponse.loadXmlFromBase64(request.getParameter("SAMLResponse"));
            samlResponse.setDestinationUrl(request.getRequestURL().toString());

            if (samlResponse.isValid()) {
                String username = samlResponse.getNameId();
                // get user
                User user = dmImpl.getUserByUsername(username);
                if (user == null && userProvisioningEnabled) {
                    // user does not exist, provision
                    user = new User();
                    user.setId(username);
                    user.setUsername(username);
                    user.setTimeZone("0");
                    user.setActive(1);
                    attrEmail = (attrEmail != null && !attrEmail.isEmpty()) ? attrEmail : "email";
                    String email = samlResponse.getAttribute(attrEmail);
                    if (email != null) {
                        if (email.startsWith("[")) {
                            email = email.substring(1, email.length()-1);
                        }
                        user.setEmail(email);
                    }
                    attrFirstName = (attrFirstName != null && !attrFirstName.isEmpty()) ? attrFirstName : "User.FirstName";
                    String firstName = samlResponse.getAttribute(attrFirstName);
                    if (firstName != null) {
                        if (firstName.startsWith("[")) {
                            firstName = firstName.substring(1, firstName.length()-1);
                        }
                        user.setFirstName(firstName);
                    }
                    attrLastName = (attrLastName != null && !attrLastName.isEmpty()) ? attrLastName : "User.LastName";
                    String lastName = samlResponse.getAttribute(attrLastName);
                    if (lastName != null) {
                        if (lastName.startsWith("[")) {
                            lastName = lastName.substring(1, lastName.length()-1);
                        }
                        user.setLastName(lastName);
                    }
                    // set role
                    RoleDao roleDao = (RoleDao)AppUtil.getApplicationContext().getBean("roleDao");
                    Set roleSet = new HashSet();
                    Role r = roleDao.getRole("ROLE_USER");
                    if (r != null) {
                        roleSet.add(r);
                    }
                    user.setRoles(roleSet);
                    // add user
                    UserDao userDao = (UserDao)AppUtil.getApplicationContext().getBean("userDao");
                    userDao.addUser(user);
                } else if (user == null && !userProvisioningEnabled) {
                    response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
                    return;
                }
                
                // verify license
                PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
                DirectoryManagerAuthenticator authenticator = (DirectoryManagerAuthenticator) pluginManager.getPlugin(DirectoryManagerAuthenticatorImpl.class.getName());
                DirectoryManager wrapper = new DirectoryManagerWrapper(dmImpl, true);
                authenticator.authenticate(wrapper, user.getUsername(), user.getPassword());
                
                // get authorities
                Collection<Role> roles = dm.getUserRoles(username);
                List<GrantedAuthority> gaList = new ArrayList<>();
                if (roles != null && !roles.isEmpty()) {
                    for (Role role : roles) {
                        GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                        gaList.add(ga);
                    }
                }
                
                // login user
                UserDetails details = new WorkflowUserDetails(user);
                UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
                result.setDetails(details);
                SecurityContextHolder.getContext().setAuthentication(result);

                // add audit trail
                WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
                workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

                // redirect
                String relayState = request.getParameter("RelayState");
                if (relayState != null && !relayState.isEmpty()) {
                    response.sendRedirect(relayState);
                } else {
                    response.sendRedirect(request.getContextPath());
                }
            } else {
                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
            }
        } catch (Exception ex) {
            LogUtil.error(getClass().getName(), ex, "Error in SAML login");
            request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
            String url = request.getContextPath() + "/web/login?login_error=1";
            response.sendRedirect(url);
        }

    }

}
