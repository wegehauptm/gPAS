package org.emau.icmvc.ganimed.ttp.modules;

import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.ejb.SessionContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;

//import org.emau.icmvc.ganimed.ttp.psn.UserManagerBean;
import org.jboss.security.NestableGroup;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;

/**
 * 
 * LoginModule.jar
 * class has to be packaged to LoginModule.jar and and deployed as a module on the application server.
 * 
 * module.xml:
 * <module xmlns="urn:jboss:module:1.1" name="javax.security.customModule:main">
 * 
 *  <resources>
 *    <resource-root path="SOAPLoginModule.jar"/>
 *  </resources>
 *  
 *  <dependencies>
 *   <module name="org.wegehaupt"/>
 *    <module name="javax.api"/>
 *  </dependencies>
 * 
 *</module>
 *
 *standalone.xml
 *            <security-domain name="simple-auth" cache-type="default"> 
 *			    <authentication>			 
 *			        <login-module code="org.emau.icmvc.ganimed.ttp.modules.SOAPLoginModule" flag="required" module="login"/>			 
 *			    </authentication>			 
 *			</security-domain>
 *
 * @author wegehaupt, Würzburg 2018
 * 
 */
public class SOAPLoginModule implements javax.security.auth.spi.LoginModule  {
	 
	CallbackHandler handler;
	protected Subject subject;
	protected CallbackHandler callbackHandler; 
	protected Map sharedState; 
	protected Map options;
	protected boolean useFirstPass;
	protected String principalClassName;
	protected String principalClassModuleName;
	protected String jbossModuleName;
	protected Principal unauthenticatedIdentity;
	protected Principal identity;
	   /** Flag indicating if the login phase succeeded. Subclasses that override
	    the login method must set this to true on successful completion of login
	    */
	   protected boolean loginOk;
	   private static final String PASSWORD_STACKING = "password-stacking";
	   private static final String USE_FIRST_PASSWORD = "useFirstPass";
	   private static final String PRINCIPAL_CLASS = "principalClass";
	   private static final String PRINCIPAL_CLASS_MODULE = "principalClassModule";
	   private static final String UNAUTHENTICATED_IDENTITY = "unauthenticatedIdentity";
	   private static final String MODULE = "module";
	
	   
	public SOAPLoginModule () {
		System.err.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>SOAPLoginModule constructed");
	}
	
    @Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
		      Map<String,?> sharedState, Map<String,?> options){
    	
			  System.err.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>SOAPLoginModule init");
			  
		      this.subject = subject;
		      this.callbackHandler = callbackHandler;
		      this.sharedState = sharedState;
		      this.options = options;

//		      try {
//				this.subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
//			} catch (PolicyContextException e1) {
//				// TODO Auto-generated catch block
//				e1.printStackTrace();
//			}

		      
		      
		      
		      
		      String passwordStacking = (String) options.get(PASSWORD_STACKING);
		      if( passwordStacking != null && passwordStacking.equalsIgnoreCase(USE_FIRST_PASSWORD) )
		         useFirstPass = true;

		      // Check for a custom Principal implementation
		      principalClassName = (String) options.get(PRINCIPAL_CLASS);
		      principalClassModuleName = (String) options.get(PRINCIPAL_CLASS_MODULE);
		      
		      // Check for unauthenticatedIdentity option.
		      String name = (String) options.get(UNAUTHENTICATED_IDENTITY);
		      if( name != null )
		      {
		         try
		         {
		            unauthenticatedIdentity = createIdentity("GUEST");
		            System.err.println(name);
		         }
		         catch(Exception e)
		         {
		        	 e.printStackTrace();
		         }
		      }
		      for(Principal p:subject.getPrincipals())
		      {
		    	  System.err.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"+p.getName());
		      }
		      
		      jbossModuleName = (String)options.get(MODULE);
		   }
 

    @Override//recently added
    public boolean login() throws LoginException
    {
    	
    	if (callbackHandler == null) {
			throw new LoginException("Oops, callbackHandler is null");
		}
    	Callback[] callbacks = new Callback[2];
		callbacks[0] = new NameCallback("name:");
		callbacks[1] = new PasswordCallback("password:", false);
//       NameCallback nameCallback = new NameCallback("username");
//       PasswordCallback passwordCallback = new PasswordCallback("password", false);
		
		try {
			callbackHandler.handle(callbacks);
		} catch (IOException e) {
			throw new LoginException("Oops, IOException calling handle on callbackHandler");
		} catch (UnsupportedCallbackException e) {
			throw new LoginException("Oops, UnsupportedCallbackException calling handle on callbackHandler");
		}

		NameCallback nameCallback = (NameCallback) callbacks[0];
		PasswordCallback passwordCallback = (PasswordCallback) callbacks[1];

		String nameCB = nameCallback.getName();
		String passwordCB = new String(passwordCallback.getPassword());
		
		System.err.println(nameCB +" XXX "+ passwordCB);
		
       String identityStr=null;
       System.err.println("----------------------------------------login----------------------------------------");
       loginOk = false;
       String username=(String)sharedState.get("javax.security.auth.login.name");
       String password=(String)sharedState.get("javax.security.auth.login.password");
       if(username==null)
    	   System.err.println("username is null");
       else
    	   System.err.println("username is not null");
       if(password==null)
    	   System.err.println("password is null");
       else
    	   System.err.println("password is not null");
       
       System.err.println("subject passsword "+subject.getPrivateCredentials(String.class));
//       if( username instanceof Principal )
//           identity = (Principal) username;
       if( username instanceof String )
           identityStr = (String) username;
       if(identity==null)
    	   identity=new SamplePrincipal(nameCB);
       if(identity==null)
    	   System.err.println("identity is null");
       
       System.err.println("subject passsword "+subject.getPrivateCredentials(String.class));
       // If useFirstPass is true, look for the shared password
       if( useFirstPass == true )
       {
    	   if(Math.random()>0.001)
    	   {
    		   loginOk = true;
    		   return true;    		   
    	   }
          try
          {
             Object identity = sharedState.get("javax.security.auth.login.name");
             Object credential = sharedState.get("javax.security.auth.login.password");
             if( identity != null && credential != null )
             {
                loginOk = true;
//                UserManagerBean umb=new UserManagerBean();
//                
//                try {
//                	umb.findUser(identity.toString(), credential.toString());                	
//                }catch (Exception e) {
//                	e.printStackTrace();
//                }
                return true;
             }
             // Else, fall through and perform the login
          }
          catch(Exception e)
          {   // Dump the exception and continue
        	  System.err.println("login failed");
          }
       }
       else
    	   System.err.println("-------------------------------------------------firstPass is false");
       return false;
    }

    protected Principal getIdentity()
    {
       return identity;
    }
    
	@Override	
	public boolean commit() throws LoginException {
		System.err.println("login ok");
	      if( loginOk == false )
	         return false;
	      Set<Principal> principals = subject.getPrincipals();
	      Principal identity = getIdentity();
	      principals.add(identity);
	      // add role groups returned by getRoleSets.
	      Group[] roleSets = getRoleSets(identity.getName());
	      for(int g = 0; g < roleSets.length; g ++)
	      {
	         Group group = roleSets[g];
	         String name = group.getName();
	         Group subjectGroup = createGroup(name, principals);
	         if( subjectGroup instanceof NestableGroup )
	         {
	            /* A NestableGroup only allows Groups to be added to it so we
	            need to add a SimpleGroup to subjectRoles to contain the roles
	            */
	            SimpleGroup tmp = new SimpleGroup("Roles");
	            subjectGroup.addMember(tmp);
	            subjectGroup = tmp;
	         }
	         // Copy the group members to the Subject group
	         Enumeration<? extends Principal> members = group.members();
	         while( members.hasMoreElements() )
	         {
	            Principal role = (Principal) members.nextElement();
	            subjectGroup.addMember(role);
	         }
	      }
	       // add the CallerPrincipal group if none has been added in getRoleSets
	       Group callerGroup = getCallerPrincipalGroup(principals);
	       if (callerGroup == null)
	       {
	           callerGroup = new SimpleGroup(SecurityConstants.CALLER_PRINCIPAL_GROUP);
	           callerGroup.addMember(identity);
	           principals.add(callerGroup);
	       }
	       return true;
	}

	@Override
	public boolean abort() throws LoginException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean logout() throws LoginException {
		// TODO Auto-generated method stub
		return false;
	}
	
	@SuppressWarnings("unchecked")
	protected static Principal createIdentity(String username) throws Exception
   {
      Principal p = null;
      p = new SimplePrincipal(username);
      return p;
   }
	
   protected Group getCallerPrincipalGroup(Set<Principal> principals)
   {
      Group callerGroup = null;
      for (Principal principal : principals)
      {
         if (principal instanceof Group)
         {
            Group group = Group.class.cast(principal);
            if (group.getName().equals(SecurityConstants.CALLER_PRINCIPAL_GROUP))
            {
               callerGroup = group;
               break;
            }
         }
      }
      return callerGroup;
   }

	
	
	/** Find or create a Group with the given name. Subclasses should use this
    method to locate the 'Roles' group or create additional types of groups.
    @return A named Group from the principals set.
    */
   protected Group createGroup(String name, Set<Principal> principals)
   {
      Group roles = null;
      Iterator<Principal> iter = principals.iterator();
      while( iter.hasNext() )
      {
         Object next = iter.next();
         if( (next instanceof Group) == false )
            continue;
         Group grp = (Group) next;
         if( grp.getName().equals(name) )
         {
            roles = grp;
            break;
         }
      }
      // If we did not find a group create one
      if( roles == null )
      {
         roles = new SimpleGroup(name);
         principals.add(roles);
      }
      return roles;
   }
	
	static Group[] getRoleSets(String targetUser)
	   {
		  char roleGroupSeperator='.';
		  Properties roles = new Properties();
		  roles.setProperty("admin", "Admin");
	      Enumeration<?> users = roles.propertyNames();
	      SimpleGroup rolesGroup = new SimpleGroup("Roles");
	      ArrayList<Group> groups = new ArrayList<Group>();
	      groups.add(rolesGroup);
	      while (users.hasMoreElements() && targetUser != null)
	      {
	         String user = (String) users.nextElement();
	         String value = roles.getProperty(user);

	         // See if this entry is of the form targetUser[.GroupName]=roles
	         //JBAS-3742 - skip potential '.' in targetUser
	         int index = user.indexOf(roleGroupSeperator, targetUser.length());
	         boolean isRoleGroup = false;
	         boolean userMatch = false;
	         if (index > 0 && targetUser.regionMatches(0, user, 0, index) == true)
	            isRoleGroup = true;
	         else
	            userMatch = targetUser.equals(user);

	         String groupName = "Roles";
	          // Check for username.RoleGroup pattern
	          if (isRoleGroup == true)
	         {
	            groupName = user.substring(index + 1);
	             if (groupName.equals("Roles"))
	            {
	               System.err.println("doing nothing");
	            }
	            else
	            {
	               SimpleGroup group = new SimpleGroup(groupName);
	               groups.add(group);
	            }
	         }
	         else if (userMatch == true)
	         {
	            // Place these roles into the Default "Roles" group
	         }
	      }
	      Group[] roleSets = new Group[groups.size()];
	      groups.toArray(roleSets);
	      return roleSets;
	   }

	   /** Execute the rolesQuery against the dsJndiName to obtain the roles for
	    the authenticated user.
	     
	    @return Group[] containing the sets of roles
	    */
	   static Group[] getRoleSets(String username, String dsJndiName, String txManagerJndiName,
	      String rolesQuery)
	      throws LoginException
	   {
	      return getRoleSets(username, dsJndiName, txManagerJndiName, rolesQuery, false);
	   }

	   /** Execute the rolesQuery against the dsJndiName to obtain the roles for
	    the authenticated user.
	     
	    @return Group[] containing the sets of roles
	    */
	   static Group[] getRoleSets(String username, String dsJndiName, String txManagerJndiName,
	      String rolesQuery, boolean suspendResume)
	      throws LoginException
	   {
	      return getRoleSetsImpl(username, dsJndiName, txManagerJndiName, rolesQuery, suspendResume);
	   }
 
    
	   static Group[] getRoleSetsImpl(String username, String dsJndiName, String txManagerJndiName,
			     String rolesQuery, boolean suspendResume) {

		   Group[] roleSets = { new SimpleGroup("Roles") };
		   return roleSets;
	   }
}
