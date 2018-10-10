package org.emau.icmvc.ganimed.ttp.psn;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;
import javax.annotation.security.PermitAll;
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
	public HashMap<Long, String> listUsers() {
		HashMap<Long,String> result = new HashMap<Long, String>();
		if (logger.isDebugEnabled()) {
			logger.debug("listUsers called");
		}
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

	@Override
	public String findUser(String username, String password) throws InvalidUserNameException, UnknownUserException, WrongPasswordException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username)) {			
			String message = "Username not found";
			logger.warn(message);
			throw new UnknownUserException(message);}
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

	@Override
	public String findUserByName(String username) throws InvalidUserNameException, UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
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

	@Override
	public void checkUserName(String username) throws InvalidUserNameException {
		if(username.matches("[^\\w\\s]]"))
			throw new InvalidUserNameException();
	}
	
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
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
		Root<USR> root = criteriaQuery.from(USR.class);
		criteriaQuery.select(root);
		criteriaQuery.where(criteriaBuilder.equal(root.get(USR_.username), username));
		USR user = em.createQuery(criteriaQuery).getSingleResult();
		return user.isAdmin();
	}

	@Override
	public Boolean isVerified(String username) throws InvalidUserNameException, UnknownUserException {
		HashMap<Long,String> result = listUsers();
		if(!result.containsValue(username))
			throw new UnknownUserException();
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
		Root<USR> root = criteriaQuery.from(USR.class);
		criteriaQuery.select(root);
		criteriaQuery.where(criteriaBuilder.equal(root.get(USR_.username), username));
		USR user = em.createQuery(criteriaQuery).getSingleResult();
		return user.isVerified();
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
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<USR> criteriaQuery = criteriaBuilder.createQuery(USR.class);
		Root<USR> root = criteriaQuery.from(USR.class);
		criteriaQuery.select(root);
		criteriaQuery.where(criteriaBuilder.equal(root.get(USR_.username), username));
		USR user = em.createQuery(criteriaQuery).getSingleResult();
		return user.getPassword();
	}
}
