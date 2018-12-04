package org.emau.icmvc.ganimed.ttp.psn;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.annotation.security.DeclareRoles;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ejb.EJB;
import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.enterprise.context.SessionScoped;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidUserNameException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownUserException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UserAlreadyExistsException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.WrongPasswordException;
import org.emau.icmvc.ganimed.ttp.psn.model.RolleBean;
import org.emau.icmvc.ganimed.ttp.psn.model.RolleBean_;
import org.emau.icmvc.ganimed.ttp.psn.model.USR;
import org.emau.icmvc.ganimed.ttp.psn.model.USR_;
import org.jboss.security.annotation.SecurityDomain;
import org.jboss.ws.api.annotation.WebContext;
import org.apache.log4j.Logger;

@WebService(name = "userService")
@SOAPBinding(style = SOAPBinding.Style.RPC)
@Stateless
@Remote(UserManager.class)
@PersistenceContext(name = "users")
@DeclareRoles(value={"Admin","User"})
@SecurityDomain(value="security-beispiel-domain")
@WebContext(authMethod="BASIC", secureWSDLAccess = false)
@PermitAll
@EJB(name="USR", beanInterface=UserManager.class)
public class UserManagerBean implements UserManager,Serializable{
	
	private static final long serialVersionUID = -8160832001659277122L;

	private static final Logger logger = Logger.getLogger(UserManagerBean.class);
	
	@PersistenceContext
	private EntityManager em;
	private static final Object emSynchronizerDummy = new Object();
	
	boolean isLoggedIn=false;
	
	@Resource
	WebServiceContext webServiceContext;

	@Override
	public void addUser(String username, String password) throws InvalidUserNameException, UserAlreadyExistsException {
		HashMap<Long,String> result = listUsers();
		if(result.containsValue(username))
			throw new UserAlreadyExistsException();
		if (logger.isDebugEnabled()) {
			logger.debug("try to create a new user " + username + ".");
		}		
		synchronized (emSynchronizerDummy) {			
			USR myUser = new USR(-1L,username, password);
			if (logger.isDebugEnabled()) {
				logger.debug("new user created: " + username);
			}
			em.persist(myUser);
		}
		if (logger.isInfoEnabled()) {
			logger.info("new user '" + username + "' persisted");
		}
	}

	@Override
	public void deleteUser(String username, String password) throws InvalidUserNameException, UnknownUserException{		
		HashMap<Long, String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		Long userId=-1L;
		for(Map.Entry<Long, String> singleUser:result.entrySet())
			if(singleUser.getValue().equals(username))
				userId=singleUser.getKey();
		USR myUser = em.find(USR.class, userId);
			synchronized (emSynchronizerDummy) {		
				em.remove(myUser);
			}
	}
	
	@Override
	@RolesAllowed("Admin")
	public void deleteUserAsAdmin(String username) throws InvalidUserNameException, UnknownUserException{		
		HashMap<Long, String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		Long userId=-1L;
		for(Map.Entry<Long, String> singleUser:result.entrySet())
			if(singleUser.getValue().equals(username))
				userId=singleUser.getKey();
		USR myUser = em.find(USR.class, userId);
			synchronized (emSynchronizerDummy) {		
				em.remove(myUser);
			}
	}
	

	@Override
	public HashMap<Long, String> listUsers() {
		HashMap<Long,String> result = new HashMap<Long, String>();
		if (logger.isDebugEnabled()) {
			logger.debug("listUsers called");
		}
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
			Root<USR> root = criteriaQuery.from(USR.class);
			criteriaQuery.select(root);
			List<USR> users = em.createQuery(criteriaQuery).getResultList();
			for (USR singleUser : users) {
				result.put(singleUser.getId(), singleUser.getUsername());
			}
			if (logger.isDebugEnabled()) {
				logger.debug("listDomains returns " + result.size() + " results");
			}
			return result;
		}
	}

	@Override
	public String findUser(String username, String password) throws InvalidUserNameException, UnknownUserException, WrongPasswordException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username)) {			
			String message = "Username not found";
			logger.warn(message);
			throw new UnknownUserException(message);}
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
			Root<USR> root = criteriaQuery.from(USR.class);
			criteriaQuery.select(root);
			criteriaQuery.where(criteriaBuilder.and(
						criteriaBuilder.equal(root.get(USR_.username), username),
						criteriaBuilder.equal(root.get(USR_.password), password)));		
			USR user =null;
			try {
				user = em.createQuery(criteriaQuery).getSingleResult();
			} catch (NoResultException e) {
				throw new WrongPasswordException();
			}
			return user.getUsername();
		}
	}

	@Override
	public String findUserByName(String username) throws InvalidUserNameException, UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
			Root<USR> root = criteriaQuery.from(USR.class);
			criteriaQuery.select(root);
			criteriaQuery.where(criteriaBuilder.equal(root.get(USR_.username), username));
			USR user =null;
			try {
				user = em.createQuery(criteriaQuery).getSingleResult();
			} catch (NoResultException e) {
				throw new UnknownUserException();
			}
			return user.getUsername();
		}
	}

	@Override
	public void checkUserName(String username) throws InvalidUserNameException {
		if(username.matches("[^\\w\\s]]"))
			throw new InvalidUserNameException();
	}
	
	//is not used...
	@Override
	public void loginForSOAP() throws InvalidUserNameException, WrongPasswordException{
		MessageContext messageContext = webServiceContext.getMessageContext();
		        // get request headers
		        Map<?,?> requestHeaders = (Map<?,?>) messageContext.get(MessageContext.HTTP_REQUEST_HEADERS);
		        List<?> usernameList = (List<?>) requestHeaders.get("username");
		        List<?> passwordList = (List<?>) requestHeaders.get("password");
		        String username = "";
		        String password = "";
		        if (usernameList != null) {
		            username = usernameList.get(0).toString();
		        }
		        if (passwordList != null) {
		            password = passwordList.get(0).toString();
		        }
		        try {
		        findUser(username, password);
		        isLoggedIn=true;
		        }catch (Exception e) {
		        	isLoggedIn=false;
		        	e.printStackTrace();		        	
		        }
	}

	@Override
	public boolean isLoggedIn() {
		return isLoggedIn;
	}

	@Override
	public void changePassword(String username, String passChange1, String passChange2, String passChange3)
			throws WrongPasswordException, UnknownUserException, InvalidUserNameException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		String myUser=findUser(username, passChange1);
		if(myUser==null)
			throw new UnknownUserException();		
		synchronized (emSynchronizerDummy) {
			HashMap<Long, String> myUsers=listUsers();
			USR userToAlter=null;
			for(Map.Entry<Long, String> singleUser:myUsers.entrySet())
				if(singleUser.getValue().equals(username))
					userToAlter=em.find(USR.class,singleUser.getKey());
			userToAlter.setPassword(passChange3);
			if (logger.isDebugEnabled()) {
				logger.debug("user password changed: " + username);
			}
			em.merge(userToAlter);
		}
		if (logger.isInfoEnabled()) {
			logger.info("new user '" + username + "' persisted");
		}
	}
	
	@Override
	public List<String> getRoles(String username) throws InvalidUserNameException, UnknownUserException {
		em.clear();
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		ArrayList<String> returnList=new ArrayList<>();
		synchronized (emSynchronizerDummy) {
			HashMap<Long, String> myUsers=listUsers();
			USR user=null;
			for(Map.Entry<Long, String> singleUser:myUsers.entrySet())
				if(singleUser.getValue().equals(username))
					user=em.find(USR.class,singleUser.getKey());
			for(RolleBean rolle: user.getRollen())
				if(rolle!=null && rolle.getRolle()!=null)
					returnList.add(rolle.getRolle());
		}
		return returnList;
	}
	
	@Override
	public Boolean hasRole(String user, String role) throws InvalidUserNameException, UnknownUserException {
		System.err.println("user "+user +" has roles:"+getRoles(user));
		return getRoles(user).contains(role);
	}
	
	@Override
	public List<String> getAllRoles() {
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<RolleBean> criteriaQuery = criteriaBuilder.createQuery(RolleBean.class);
			Root<RolleBean> root = criteriaQuery.from(RolleBean.class);
			criteriaQuery.select(root);
			criteriaQuery.distinct(true);
			List<RolleBean> roles = em.createQuery(criteriaQuery).getResultList();
			ArrayList<String> returnList=new ArrayList<>();
			for(RolleBean role:roles)
			{
				returnList.add(role.getRolle());
			}
			return returnList;
		}
	}

	@Override
	@RolesAllowed("Admin")
	public void setVerified(String username) throws InvalidUserNameException, UnknownUserException {		
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		String myUser=findUserByName(username);
		if(myUser==null)
			throw new UnknownUserException();		
		synchronized (emSynchronizerDummy) {
			HashMap<Long, String> myUsers=listUsers();
			USR userToAlter=null;
			for(Map.Entry<Long, String> singleUser:myUsers.entrySet())
				if(singleUser.getValue().equals(username))
					userToAlter=em.find(USR.class,singleUser.getKey());
			userToAlter.setVerified(true);
			if (logger.isDebugEnabled()) {
				logger.debug("user changed to verified: " + username);
			}
			em.merge(userToAlter);
		}
		if (logger.isInfoEnabled()) {
			logger.info("user '" + username + "' persisted");
		}
	}

	@Override
	public void setUnverified(String username) throws InvalidUserNameException, UnknownUserException {		
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		String myUser=findUserByName(username);
		if(myUser==null)
			throw new UnknownUserException();		
		synchronized (emSynchronizerDummy) {
			HashMap<Long, String> myUsers=listUsers();
			USR userToAlter=null;
			for(Map.Entry<Long, String> singleUser:myUsers.entrySet())
				if(singleUser.getValue().equals(username))
					userToAlter=em.find(USR.class,singleUser.getKey());
			userToAlter.setVerified(false);
			if (logger.isDebugEnabled()) {
				logger.debug("user password changed: " + username);
			}
			em.merge(userToAlter);
		}
		if (logger.isInfoEnabled()) {
			logger.info("user '" + username + "' persisted");
		}
	}

	@Override
	public Boolean isAdmin(String username) throws InvalidUserNameException, UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
			Root<USR> root = criteriaQuery.from(USR.class);
			criteriaQuery.select(root);
			criteriaQuery.where(criteriaBuilder.equal(root.get(USR_.username), username));
			USR user = em.createQuery(criteriaQuery).getSingleResult();
			return user.isAdmin();
		}
	}

	@Override
	public Boolean isVerified(String username) throws InvalidUserNameException, UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
			Root<USR> root = criteriaQuery.from(USR.class);
			criteriaQuery.select(root);
			criteriaQuery.where(criteriaBuilder.equal(root.get(USR_.username), username));
			USR user = em.createQuery(criteriaQuery).getSingleResult();
			return user.isVerified();
		}
	}

	@Override
	public void setAdmin(String username) throws InvalidUserNameException, UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		String myUser=findUserByName(username);
		if(myUser==null)
			throw new UnknownUserException();		
		synchronized (emSynchronizerDummy) {
			HashMap<Long, String> myUsers=listUsers();
			USR userToAlter=null;
			for(Map.Entry<Long, String> singleUser:myUsers.entrySet())
				if(singleUser.getValue().equals(username))
					userToAlter=em.find(USR.class,singleUser.getKey());
			userToAlter.setAdmin(true);
			if (logger.isDebugEnabled()) {
				logger.debug("user changed to verified: " + username);
			}
			em.merge(userToAlter);
		}
		if (logger.isInfoEnabled()) {
			logger.info("user '" + username + "' persisted");
		}
	}

	@Override
	public void setNotAdmin(String username) throws InvalidUserNameException, UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		String myUser=findUserByName(username);
		if(myUser==null)
			throw new UnknownUserException();		
		synchronized (emSynchronizerDummy) {
			HashMap<Long, String> myUsers=listUsers();
			USR userToAlter=null;
			for(Map.Entry<Long, String> singleUser:myUsers.entrySet())
				if(singleUser.getValue().equals(username))
					userToAlter=em.find(USR.class,singleUser.getKey());
			userToAlter.setAdmin(false);
			if (logger.isDebugEnabled()) {
				logger.debug("user changed to verified: " + username);
			}
			em.merge(userToAlter);
		}
		if (logger.isInfoEnabled()) {
			logger.info("user '" + username + "' persisted");
		}
	}
	
	public String getPassword(String username) throws UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
			Root<USR> root = criteriaQuery.from(USR.class);
			criteriaQuery.select(root);
			criteriaQuery.where(criteriaBuilder.equal(root.get(USR_.username), username));
			USR user = em.createQuery(criteriaQuery).getSingleResult();
			return user.getPassword();
		}
	}

	@Override
	@RolesAllowed("Admin")
	public void toggleRole(String username, String role) throws InvalidUserNameException, UnknownUserException {
		boolean done=false;
		if(role==null||username==null) {
			System.err.println("toglleRole is quitting!");
			return;
		}
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		String myUser=findUserByName(username);
		if(myUser==null)
			throw new UnknownUserException();		
		synchronized (emSynchronizerDummy) {
			HashMap<Long, String> myUsers=listUsers();
			USR userToAlter=null;
			for(Map.Entry<Long, String> singleUser:myUsers.entrySet())
				if(singleUser.getValue().equals(username))
					userToAlter=em.find(USR.class,singleUser.getKey());
			
			if(userToAlter==null)
				System.err.println("userToAlter is null!!!");
			
			Collection<RolleBean> newRolesCollection=userToAlter.getRollen();
			
			//delete specific role
			if(hasRole(username, role)) {
				System.err.println("trying to delete - user:"+username+" role:"+role);
				Iterator<RolleBean> iter = newRolesCollection.iterator();
				while (iter.hasNext()) {
					RolleBean rl=iter.next();					
					if(role.equals(rl.getRolle())) {
						iter.remove();
						done=true;
					}
				}
			}
			System.err.println("removing is done:" + done + " newRolesCollection:");
			for(RolleBean r:newRolesCollection)
				System.err.print("rolle:"+r.getRolle().toString()+" ");
			RolleBean newRole;
			int roleID=-1;
			//add specific role
			if(done==false) {
				
				CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
				CriteriaQuery<RolleBean> criteriaQuery = criteriaBuilder.createQuery(RolleBean.class);
				Root<RolleBean> root = criteriaQuery.from(RolleBean.class);
				criteriaQuery.select(root);
				criteriaQuery.distinct(true);
				List<RolleBean> roles = em.createQuery(criteriaQuery).getResultList();
				for(RolleBean rlforID:roles)
				{
					if(rlforID.getRolle().equals(role))
						roleID=rlforID.getId();
				}								
				newRolesCollection.add(newRole=new RolleBean());
				newRole.setRolle(role);
				newRole.setId(roleID);
			}
			
					
			userToAlter.setRollen(newRolesCollection);
			if (logger.isDebugEnabled()) {
				logger.debug("user roles changed: " + username);
			}
			em.merge(userToAlter);
		}
		if (logger.isInfoEnabled()) {
			logger.info("user '" + username + "' persisted");
		}
	}

}
