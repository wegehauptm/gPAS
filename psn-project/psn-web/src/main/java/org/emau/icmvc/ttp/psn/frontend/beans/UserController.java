package org.emau.icmvc.ttp.psn.frontend.beans;

//import java.io.IOException;
//import java.security.Principal;
//import java.text.MessageFormat;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.Hashtable;
//import java.util.List;
//import java.util.Map;
//import java.util.Properties;
//import java.util.ResourceBundle;
//import java.util.concurrent.Callable;
//
//import javax.annotation.PostConstruct;
//import javax.ejb.EJB;
//import javax.el.ELContext;
//import javax.faces.application.FacesMessage;
//import javax.faces.bean.ManagedBean;
//import javax.faces.bean.ManagedProperty;
//import javax.faces.bean.SessionScoped;
//import javax.faces.context.ExternalContext;
//import javax.faces.context.FacesContext;
//import javax.faces.event.ActionEvent;
//import javax.faces.event.AjaxBehaviorEvent;
//import javax.naming.Context;
//import javax.naming.InitialContext;
//import javax.naming.NamingException;
//import javax.servlet.http.HttpServletRequest;
//
//import org.emau.icmvc.ganimed.ttp.psn.PSNManager;
//import org.emau.icmvc.ganimed.ttp.psn.UserManager;
//import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidUserNameException;
//import org.emau.icmvc.ganimed.ttp.psn.exceptions.PasswordsDoNotMatchException;
//import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownUserException;
//import org.emau.icmvc.ganimed.ttp.psn.exceptions.UserAlreadyExistsException;
//import org.emau.icmvc.ganimed.ttp.psn.exceptions.WrongPasswordException;
//import org.emau.icmvc.ttp.psn.frontend.datamodel.User;
////zuletzt auskommentiert
////import org.jboss.ejb.client.ContextSelector;
////import org.jboss.ejb.client.EJBClientConfiguration;
////import org.jboss.ejb.client.EJBClientContext;
////import org.jboss.ejb.client.PropertiesBasedEJBClientConfiguration;
////import org.jboss.ejb.client.remoting.ConfigBasedEJBClientContextSelector;
//
////import org.jboss.security.SecurityContextAssociation;
////import org.jboss.security.plugins.JBossSecurityContext;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.wildfly.common.context.ContextManager;
//import org.wildfly.security.WildFlyElytronProvider;
////import org.wildfly.naming.client.InitialContext;
////import org.jboss.security.jndi.JndiLoginInitialContextFactory;
////import org.wildfly.common.*;
////import org.wildfly.security.*;
////import org.wildfly.naming.*;
////import org.jboss.as.naming.*;
////import org.jboss.as.security.*;
////import org.jboss.remoting3.RemotingOptions;
//import org.wildfly.security.auth.client.AuthenticationConfiguration;
//import org.wildfly.security.auth.client.AuthenticationContext;
//import org.wildfly.security.auth.client.MatchRule;
//import org.wildfly.security.sasl.SaslMechanismSelector;
//
////import org.jboss.security.client.SecurityClient;
////import org.jboss.security.client.SecurityClientFactory;
//
////import org.jboss.naming.*;
////import javax.naming.Context;
////import javax.naming.InitialContext;
////import javax.naming.NamingException;

import java.io.IOException;
import java.security.Principal;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.concurrent.Callable;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.el.ELContext;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.ActionEvent;
import javax.faces.event.AjaxBehaviorEvent;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.spi.NamingManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.emau.icmvc.ganimed.ttp.psn.PSNManager;
import org.emau.icmvc.ganimed.ttp.psn.UserManager;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidGeneratorException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidPSNException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidUserNameException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.PSNNotFoundException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.PasswordsDoNotMatchException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownDomainException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownUserException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UserAlreadyExistsException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.ValueIsAnonymisedException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.WrongPasswordException;
import org.emau.icmvc.ttp.psn.frontend.datamodel.User;
//zuletzt auskommentiert
//import org.jboss.ejb.client.ContextSelector;
//import org.jboss.ejb.client.EJBClientConfiguration;
//import org.jboss.ejb.client.EJBClientContext;
//import org.jboss.ejb.client.PropertiesBasedEJBClientConfiguration;
//import org.jboss.ejb.client.remoting.ConfigBasedEJBClientContextSelector;

//import org.jboss.security.SecurityContextAssociation;
//import org.jboss.security.plugins.JBossSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wildfly.common.context.ContextManager;
import org.wildfly.security.WildFlyElytronProvider;
//import org.wildfly.naming.client.InitialContext;
//import org.jboss.security.jndi.JndiLoginInitialContextFactory;
import org.wildfly.common.*;
import org.wildfly.security.*;
import org.wildfly.naming.*;
import org.wildfly.naming.client.WildFlyInitialContext;
import org.wildfly.naming.client.WildFlyInitialContextFactoryBuilder;
//import org.jboss.as.naming.*;
//import org.jboss.as.security.*;
//import org.jboss.remoting3.RemotingOptions;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.sasl.SaslMechanismSelector;

//import org.jboss.security.client.SecurityClient;
//import org.jboss.security.client.SecurityClientFactory;

//import org.jboss.naming.*;
//import javax.naming.Context;
import javax.naming.InitialContext;
//import javax.naming.NamingException;


@ManagedBean(name = "UserController")
@SessionScoped
public class UserController {
	@EJB(lookup = "java:global/gpas/psn-ejb/UserManagerBean!org.emau.icmvc.ganimed.ttp.psn.UserManager")
	private UserManager userManager;

	private final Logger logger = LoggerFactory.getLogger(UserController.class);
	
	private HashMap<Long,String> users;
	private ResourceBundle messages;
	private String selectedUser;
	private User selectedTableUser;
	private List<User> userTableList;
	private String newUser;
	private String newPassword;
	private String passwordRepeat;
	private String username;
	private String password;
	private String passChange1;
	private String passChange2;
	private String passChange3;

	private boolean isLoggedIn=false;
	private InitialContext securityContext=null;
	
	public UserController() {
		
	}
	
	@PostConstruct
	public void init() {
		System.err.println("----------------------------Session been is NEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEW----------------------------");
		messages = ResourceBundle.getBundle("messages");
		updateAll();
	}

	/**
	 * update the full bean
	 */
	public void updateAll() {
		users = userManager.listUsers();
		selectedUser = null;
		//isLoggedIn=false;
		try {
			System.err.println("----------------------------new InitalContext is a FAAAAAAAAAAAAAAAAAAAAAAAAAAAAKE----------------------------");
			securityContext=new InitialContext();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
	}
	
	public void deleteSelectedUser() {
		FacesContext context = FacesContext.getCurrentInstance();
		Object[] args = { selectedUser };
		try {
			userManager.deleteUser(selectedUser, password);
			isLoggedIn=false;
			users = userManager.listUsers();
			selectedUser=null;
			context.addMessage("deletion",
					new FacesMessage(FacesMessage.SEVERITY_INFO, new MessageFormat(messages.getString("psn.info.valueDeleted")).format(args), ""));
			selectedUser = null;
			if (logger.isDebugEnabled()) {
				logger.debug("deleted user");
			}
			if (logger.isInfoEnabled()) {
				logger.info("deleted user");
			}
		} catch (InvalidUserNameException e) {
			context.addMessage("deletion",
					new FacesMessage(FacesMessage.SEVERITY_INFO, new MessageFormat(messages.getString("psn.error.deleteForbidden")).format(args), ""));
			if (logger.isErrorEnabled())
				logger.error("", e);
		} catch (UnknownUserException e) {
			
			context.addMessage("deletion",
					new FacesMessage(FacesMessage.SEVERITY_INFO, new MessageFormat(messages.getString("psn.error.valueNotFound")).format(args), ""));
			if (logger.isErrorEnabled())
				logger.error("", e);
		}
	}
	
	public void addUser(ActionEvent event) {
		FacesContext context = FacesContext.getCurrentInstance();
		Object[] args = { newUser, newPassword};
		try {
			userManager.addUser(newUser,newPassword);
			users = userManager.listUsers();
			context.addMessage("psnValuePairsMessage", new FacesMessage(FacesMessage.SEVERITY_INFO,
					new MessageFormat(messages.getString("psn.info.psnValuePairInserted")).format(args), ""));
			selectedUser = userManager.findUserByName(newUser);
			if (logger.isDebugEnabled()) {
				logger.debug("psn value pair inserted");
			}
		} catch (UserAlreadyExistsException e) {
			context.addMessage("loginMessage", new FacesMessage(FacesMessage.SEVERITY_ERROR, messages.getString("user.info.userAlreadyExists"), null));
			if (logger.isErrorEnabled())
				logger.error("", e);
		} catch (InvalidUserNameException e) {
			context.addMessage("loginMessage",
					new FacesMessage(FacesMessage.SEVERITY_ERROR, messages.getString("general.error.unexpectedError"), e.getMessage()));
			if (logger.isErrorEnabled())
				logger.error("", e);
		} catch (UnknownUserException e) {
			context.addMessage("loginMessage",
					new FacesMessage(FacesMessage.SEVERITY_ERROR, messages.getString("general.error.unexpectedError"), e.getMessage()));
			if (logger.isErrorEnabled())
				logger.error("", e);
		} 
	}
	
	public void login() throws IOException {
        FacesContext fContext = FacesContext.getCurrentInstance();
        ExternalContext externalContext = fContext.getExternalContext();
        HttpServletRequest request = (HttpServletRequest) externalContext.getRequest();    
        
        try {
        	if (!NamingManager.hasInitialContextFactoryBuilder()) {
        		NamingManager.setInitialContextFactoryBuilder(new WildFlyInitialContextFactoryBuilder());
            }			
		} catch (NamingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        
        try {
            selectedUser = userManager.findUser(username, password);
            if(!isVerfied())
            {
    			fContext.addMessage("loginMessage", new FacesMessage(messages.getString("user.info.getUserNotVerified")));
            	return;
            }
            externalContext.getSessionMap().put("user", username);
            externalContext.redirect(externalContext.getRequestContextPath() + "/html/app/index.xhtml");
            isLoggedIn=true;
        }catch(Exception e)
        {
        	e.printStackTrace();
        }
//            final Hashtable<String, Object> jndiProperties = new Hashtable<>();

//			  System.setProperty("jboss.ejb.client.properties.file.path", "/path/to/properties/file");
            
//            Properties clientProperties = new Properties();
//            //clientProperties.put("endpoint.name", "client-endpoint");
//            clientProperties.put("remote.connectionprovider.create.options.org.xnio.Options.SSL_ENABLED", "false");
//            clientProperties.put("remote.connections", "default");
//            clientProperties.put("remote.connection.default.port", "8080");
//            clientProperties.put("remote.connection.default.host", "localhost");
//            clientProperties.put("remote.connection.default.connect.options.org.xnio.Options.SASL_POLICY_NOANONYMOUS", "false");
//            //clientProperties.put("remote.connection.default.connect.options.org.xnio.Options.SASL_DISALLOWED_MECHANISMS", "JBOSS-LOCAL-USER");
//            clientProperties.put("remote.connection.default.connect.options.org.xnio.Options.SASL_POLICY_NOPLAINTEXT", "false");
//            clientProperties.put("username", username);
//            clientProperties.put("password", password);
//
//            EJBClientConfiguration ejbClientConfiguration = new PropertiesBasedEJBClientConfiguration(clientProperties);
//            ContextSelector<EJBClientContext> contextSelector = new ConfigBasedEJBClientContextSelector(ejbClientConfiguration);
//            EJBClientContext.setSelector(contextSelector);
            
	         AuthenticationConfiguration ejbConfig = AuthenticationConfiguration.empty().useDefaultProviders().useName(username).usePassword(password).useRealm("ApplicationRealm").usePort(8080).setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("PLAIN").forbidMechanism("JBOSS-LOCAL-USER")).useProtocol("remote+http"); ;//.setSaslMechanismSelector(SaslMechanismSelector.NONE.forbidMechanism("JBOSS-LOCAL-USER")); simple-auth-realm .useRealm("ApplicationRealm") .useProviders(() -> new WildFlyElytronProvider[]{new WildFlyElytronProvider()})
	         // .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("PLAIN")) hinzugefügt
	         // create your authentication context
	         AuthenticationContext context = AuthenticationContext.empty().with(MatchRule.ALL, ejbConfig);
	        
//	         AuthenticationConfiguration superUser = AuthenticationConfiguration.empty().setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("PLAIN")).useName(UserContext.getInstance().getUsername()).usePassword(UserContext.getInstance().getPassword());
//	         final AuthenticationContext authCtx = AuthenticationContext.empty().with(MatchRule.ALL, superUser);
	         AuthenticationContext.getContextManager().setThreadDefault(context);
	         ContextManager<AuthenticationContext> contextManager = context.getInstanceContextManager(); 
	         contextManager.setGlobalDefault(context);
	         
	         
	         // create a callable that invokes an EJB
	         Callable<Void> callable = () -> {	                       
	        	 Hashtable<String, Object> properties = new Hashtable<>();
//	             properties.put("remote.connection.default.username", username);  
//	             properties.put("remote.connection.default.password",password);  
//	             properties.put(Context.SECURITY_PRINCIPAL, username); //username
//	             properties.put(Context.SECURITY_CREDENTIALS, password); //password ^----- angeblich alles falsch bei elytron
	             properties.put("jboss.naming.client.connect.timeout", "150000");
	             properties.put(Context.INITIAL_CONTEXT_FACTORY, "org.wildfly.naming.client.WildFlyInitialContextFactory"); //org.jboss.as.naming.InitialContextFactory
	             //properties.put(Context.INITIAL_CONTEXT_FACTORY, "org.jboss.naming.remote.client.InitialContextFactory");
	             //org.wildfly.security.jndi.WildFlyInitialContextFactory
	             //org.jboss.security.jndi.JndiLoginInitialContextFactory
	             properties.put(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
//	             properties.put("endpoint.name", "client-endpoint"); 
	             properties.put(Context.PROVIDER_URL, "remote+http://localhost:8080");//remote+http://: JNDI ContextFactory: ; gpas/psn-ejb; wildfly-services
	             properties.put("remote.connection.default.host", "localhost");
	             properties.put("remote.connection.default.port", "8080");
	             properties.put("remote.connection.default.connect.options.org.xnio.Options.SASL_POLICY_NOANONYMOUS", true);
	             properties.put("remote.connectionprovider.create.options.org.xnio.Options.SSL_ENABLED", false);
//	             properties.put("org.jboss.ejb.client.scoped.context", true);
//	             properties.put("jboss.naming.client.ejb.context", true);
	             //properties.put("jboss.naming.client.connect.options.org.xnio.Options.SASL_DISALLOWED_MECHANISMS", "JBOSS-LOCAL-USER");  
	             //properties.put("remote.connection.default.connect.options.org.xnio.Options.SASL_DISALLOWED_MECHANISMS", "JBOSS-LOCAL-USER");
		         

		         setSecurityContext(new InitialContext(properties));
	             PSNManager psnManager = (PSNManager) getSecurityContext().lookup("ejb:gpas/psn-ejb/PSNManagerBean!org.emau.icmvc.ganimed.ttp.psn.PSNManager");//WildFly
//	             PSNManager psnManager = (PSNManager) new InitialContext(properties).lookup("java:jboss/exported/gpas/psn-ejb/PSNManagerBean!org.emau.icmvc.ganimed.ttp.psn.PSNManager");//WildFly
//		         PSNManager psnManager = (PSNManager) new InitialContext(properties).lookup("java:global/gpas/psn-ejb/PSNManagerBean!org.emau.icmvc.ganimed.ttp.psn.PSNManager");
	             System.err.println(psnManager.getValueForDecode("96417336", "testDomain1"));
		         return null;
	         };
	         
	         
//	         SaslClientFactory s=new org.wildfly.security.sasl.util.SecurityProviderSaslClientFactory();
//			try {
//				SaslClient securityClient=s.createSaslClient(new String[]{"PLAIN"}, username, "local", "127.0.0.1", (Map)(new HashMap<String, String>()), new CallbackHandler() {
//			                @Override
//			                public void handle(final Callback[] callbacks)
//			                        throws IOException, UnsupportedCallbackException {
//			                    for (final Callback callback : callbacks) {
//			                        if (callback instanceof PasswordCallback) {
//			                            ((PasswordCallback) callback).setPassword(password.toCharArray());
//			                        } else if (callback instanceof NameCallback) {
//			                            ((NameCallback) callback).setName(username);
//			                        }
//			                    }
//			                }
//			            });
//
//				  byte[] response = securityClient.evaluateChallenge(new byte[0]);
//				  System.err.println("SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASL:"+securityClient.isComplete());
//			} catch (Exception e) {
//				// TODO Auto-generated catch block
//				System.err.println("----------------------------SecurityClientFactory does not work----------------------------");
//				e.printStackTrace();
//			}   
	         
	         // use your authentication context to run your callable
	         try {
				context.runCallable(callable);
				System.err.println("----------------------------new InitialContext is "+getSecurityContext().hashCode()+"----------------------------");
			} catch (InvalidUserNameException e) {
	        	fContext.addMessage("loginMessage", new FacesMessage(messages.getString("user.info.invalidUsername")));
	        	isLoggedIn=false;
//	        	userManager=(UserManager)context.lookup("ejb:global/gpas/psn-ejb/UserManagerBean!org.emau.icmvc.ganimed.ttp.psn.UserManager?stateful");
				e.printStackTrace();
			} catch (UnknownUserException e) {
				fContext.addMessage("loginMessage", new FacesMessage(messages.getString("user.info.getUserNotFound")));
				isLoggedIn=false;
//				userManager=(UserManager)context.lookup("ejb:global/gpas/psn-ejb/UserManagerBean!org.emau.icmvc.ganimed.ttp.psn.UserManager?stateful");
				e.printStackTrace();
			} catch (WrongPasswordException e) {
				fContext.addMessage("loginMessage", new FacesMessage(messages.getString("user.info.wrongPassword")));
				isLoggedIn=false;
//				userManager=(UserManager)context.lookup("ejb:global/gpas/psn-ejb/UserManagerBean!org.emau.icmvc.ganimed.ttp.psn.UserManager?stateful");
				e.printStackTrace();
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidGeneratorException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidPSNException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (PSNNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (UnknownDomainException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ValueIsAnonymisedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} finally{
				
			}
        }
	
//  //jndiProperties.put(Context.URL_PKG_PREFIXES, "org.jboss.naming:org.jnp.interfaces");
//  jndiProperties.put(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
//  jndiProperties.put(Context.PROVIDER_URL,"remote+http://localhost:8080");
//  jndiProperties.put(Context.SECURITY_PRINCIPAL, username);
//  jndiProperties.put(Context.SECURITY_CREDENTIALS, password);
//  //jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY, "org.jboss.security.jndi.JndiLoginInitialContextFactory");//JNDILoginIntialContextFactory is no longer supported in AS-5. See this recent discussion 
//  ////jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY, "org.jboss.as.naming.InitialContextFactory");
//  jndiProperties.put(Context.INITIAL_CONTEXT_FACTORY, "org.wildfly.naming.client.InitialContextFactory");
//  jndiProperties.put("jboss.naming.client.ejb.context", true);
//	System.err.println("----------------------------trying to set new InitalContext----------------------------");
//	try {
//		setSecurityContext(new InitialContext(jndiProperties));
//	} catch (NamingException e) {
//		System.err.println("----------------------------new InitalContext was NOOOOOOOOOOOOOOOOOOOOOOOOOOT set----------------------------");
//		e.printStackTrace();
//	}
//  System.err.println("----------------------------new InitalContext was set----------------------------");
//  System.err.println("----------------------------new InitialContext is "+getSecurityContext().hashCode()+"----------------------------");
//  usersSingleton.setSecurityContext(getSecurityContext());
  //org.jboss.remoting3.RemotingOptions.mergeOptionsIntoAuthenticationConfiguration(arg0, arg1);
  //SOAPLoginModule
  
//  Properties env = new Properties();
//  env.put(Context.URL_PKG_PREFIXES,"org.jboss.ejb.client.naming");
//  setSecurityContext(new InitialContext(env));
//  JBossSecurityContext jsc = new JBossSecurityContext("simple-auth"); // the same security domain as defined in @SecurityDomain on EJB
//  SecurityContextAssociation.setSecurityContext(jsc);
//  SecurityContextAssociation.setPrincipal(new Principal() {
//            @Override
//            public String getName() {
//                      return username;
//            }
//  });
//  SecurityContextAssociation.setCredential(password);

	
	
	public void createAccount() throws IOException {
        FacesContext context = FacesContext.getCurrentInstance();
        ExternalContext externalContext = context.getExternalContext();
        HttpServletRequest request = (HttpServletRequest) externalContext.getRequest();

        try {
//        	if (username != null && password != null)
//        		request.login(username, password);
        	userManager.checkUserName(newUser);
            try{selectedUser = userManager.findUserByName(newUser);} catch (Exception e) {selectedUser=null;}
            if(selectedUser!=null)
            	throw new UserAlreadyExistsException();
            if(newPassword==null||passwordRepeat==null)
            	throw new PasswordsDoNotMatchException();
            if(!newPassword.equals(passwordRepeat)||newPassword.equals("")||passwordRepeat.equals(""))
            	throw new PasswordsDoNotMatchException();
            userManager.addUser(newUser, newPassword);
            //externalContext.getSessionMap().put("user", username);
            externalContext.redirect(externalContext.getRequestContextPath() + "/html/app/index.xhtml");
            isLoggedIn=false;
        } 
        catch (InvalidUserNameException e) {
        	context.addMessage("loginMessage", new FacesMessage(messages.getString("user.info.invalidUsername")));
			e.printStackTrace();
		} catch (UserAlreadyExistsException e) {
			context.addMessage("loginMessage", new FacesMessage(messages.getString("user.info.userAlreadyExists")));
			e.printStackTrace();
		} catch (PasswordsDoNotMatchException e) {
			context.addMessage("loginMessage", new FacesMessage(messages.getString("user.info.wrongPassword")));
			e.printStackTrace();
		}
    }

    public void logout() throws IOException {
        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        externalContext.invalidateSession();
        externalContext.redirect(externalContext.getRequestContextPath() + "/html/app/index.xhtml");
        isLoggedIn=false;
        selectedUser=null;
        try {
			setSecurityContext(new InitialContext());
			System.err.println("----------------------------new InitalContext is plain----------------------------");
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			System.err.println("----------------------------new (plain) InitalContext is not valid----------------------------");
			e.printStackTrace();
		}                
        FacesContext facesContext = FacesContext.getCurrentInstance();
        PsnControllerV2 psnController=(PsnControllerV2) facesContext.getApplication().getELResolver().getValue(facesContext.getELContext(), null, "PsnControllerV2");
        psnController.init();
        
        AuthenticationConfiguration ejbConfig = AuthenticationConfiguration.empty().useDefaultProviders().useName("none").usePassword("blank").useRealm("ApplicationRealm").usePort(8080).setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("PLAIN").forbidMechanism("JBOSS-LOCAL-USER")).useProtocol("remote+http"); ;//.setSaslMechanismSelector(SaslMechanismSelector.NONE.forbidMechanism("JBOSS-LOCAL-USER")); simple-auth-realm .useRealm("ApplicationRealm") .useProviders(() -> new WildFlyElytronProvider[]{new WildFlyElytronProvider()})
        // .setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("PLAIN")) hinzugefügt
        // create your authentication context
        AuthenticationContext context = AuthenticationContext.empty().with(MatchRule.ALL, ejbConfig);
       
//        AuthenticationConfiguration superUser = AuthenticationConfiguration.empty().setSaslMechanismSelector(SaslMechanismSelector.NONE.addMechanism("PLAIN")).useName(UserContext.getInstance().getUsername()).usePassword(UserContext.getInstance().getPassword());
//        final AuthenticationContext authCtx = AuthenticationContext.empty().with(MatchRule.ALL, superUser);
        AuthenticationContext.getContextManager().setThreadDefault(context);
        ContextManager<AuthenticationContext> contextManager = context.getInstanceContextManager(); 
        contextManager.setGlobalDefault(context);
        
        
        // create a callable that invokes an EJB
        Callable<Void> callable = () -> {return null;};
        try {
			context.runCallable(callable);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        updateAll();
    }

    public void changePassword() throws WrongPasswordException {
    	if(passChange1==null||passChange2==null||passChange3==null)
    		throw new WrongPasswordException();
    	if(passChange1.equals("")||passChange2.equals("")||passChange3.equals(""))
    		throw new WrongPasswordException();
    	if(!passChange2.equals(passChange3))
    		throw new WrongPasswordException();
		try {
			userManager.changePassword(username, passChange1, passChange2, passChange3);
		} catch (UnknownUserException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidUserNameException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public Boolean isAdmin() throws InvalidUserNameException, UnknownUserException {
    	if(selectedUser!=null)
    		return userManager.isAdmin(selectedUser);
    	return null;
    }
    
    public Boolean isVerfied() throws InvalidUserNameException, UnknownUserException {
    	if(selectedUser!=null)
    		return userManager.isVerified(selectedUser);
    	return null;
    }
    
    public void setVerfied(String username) throws InvalidUserNameException, UnknownUserException {
    	userManager.setVerified(username);
    }
    
    public void setUnverified(String username) throws InvalidUserNameException, UnknownUserException {
    	userManager.setUnverified(username);
    }
    
    public void handleChangeVerified(AjaxBehaviorEvent e) throws InvalidUserNameException, UnknownUserException{  
    	User user = (User) e.getComponent().getAttributes().get("myuser");
    	if(!user.isVerified())
    		userManager.setVerified(user.getUsername());
    	else
    		userManager.setUnverified(user.getUsername());
	}
    
    public void handleChangeAdmin(AjaxBehaviorEvent e) throws InvalidUserNameException, UnknownUserException{  
    	User user = (User) e.getComponent().getAttributes().get("myuser");
    	if(!user.isAdmin())
    		userManager.setAdmin(user.getUsername());
    	else
    		userManager.setNotAdmin(user.getUsername());
	}
    
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	public String getNewUser() {
		return newUser;
	}

	public void setNewUser(String newUser) {
		this.newUser = newUser;
	}

	public String getNewPassword() {
		return newPassword;
	}

	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}

	public String getPasswordRepeat() {
		return passwordRepeat;
	}

	public void setPasswordRepeat(String passwordRepeat) {
		this.passwordRepeat = passwordRepeat;
	}

	public boolean isLoggedIn() {
		return isLoggedIn;
	}

	public void setLoggedIn(boolean isLoggedIn) {
		this.isLoggedIn = isLoggedIn;
	}
	
	public String getPassChange1() {
		return passChange1;
	}

	public void setPassChange1(String passChange1) {
		this.passChange1 = passChange1;
	}

	public String getPassChange2() {
		return passChange2;
	}

	public void setPassChange2(String passChange2) {
		this.passChange2 = passChange2;
	}

	public String getPassChange3() {
		return passChange3;
	}

	public void setPassChange3(String passChange3) {
		this.passChange3 = passChange3;
	}

	public List<User> getUserTableList() throws InvalidUserNameException, UnknownUserException {
		ArrayList<User> users=new ArrayList<User>();
		User newuser=null;
		for(Map.Entry<Long, String> user: userManager.listUsers().entrySet()) {
			users.add(newuser=new User(user.getKey(),user.getValue(),false,false));
			newuser.setAdmin(userManager.isAdmin(user.getValue()));
			newuser.setVerified(userManager.isVerified(user.getValue()));
		}
		userTableList=users;
		return userTableList;
	}

	public void setUserTableList(List<User> userTableList) {
		this.userTableList = userTableList;
	}

	public User getSelectedTableUser() {
		return selectedTableUser;
	}

	public void setSelectedTableUser(User selectedTableUser) {
		this.selectedTableUser = selectedTableUser;
	}

	public InitialContext getSecurityContext() {
		return securityContext;
	}

	public void setSecurityContext(InitialContext securityContext) {
		this.securityContext = securityContext;
	}

}