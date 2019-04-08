package org.emau.icmvc.ganimed.ttp.psn;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;

/*
 * ###license-information-start###
 * gPAS - a Generic Pseudonym Administration Service
 * __
 * Copyright (C) 2013 - 2017 The MOSAIC Project - Institut fuer Community Medicine der
 * 							Universitaetsmedizin Greifswald - mosaic-projekt@uni-greifswald.de
 * 							concept and implementation
 * 							l. geidel
 * 							web client
 * 							g. weiher
 * 							a. blumentritt
 * 							please cite our publications
 * 							http://dx.doi.org/10.3414/ME14-01-0133
 * 							http://dx.doi.org/10.1186/s12967-015-0545-6
 * __
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * ###license-information-end###
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Resource;
import javax.annotation.security.DeclareRoles;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.annotation.security.RunAs;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ejb.EJB;
import javax.ejb.Remote;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Expression;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.emau.icmvc.ganimed.ttp.psn.crypto.AESUtil;
import org.emau.icmvc.ganimed.ttp.psn.dto.DomainLightDTO;
import org.emau.icmvc.ganimed.ttp.psn.dto.HashMapWrapper;
import org.emau.icmvc.ganimed.ttp.psn.dto.PSNTreeDTO;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.CharNotInAlphabetException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.DBException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.DeletionForbiddenException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidAlphabetException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidCheckDigitClassException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidGeneratorException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidPSNException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.PSNNotFoundException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownDomainException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownValueException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.ValueIsAnonymisedException;
import org.emau.icmvc.ganimed.ttp.psn.generator.Generator;
import org.emau.icmvc.ganimed.ttp.psn.generator.GeneratorProperties;
import org.emau.icmvc.ganimed.ttp.psn.internal.AnonymDomain;
import org.emau.icmvc.ganimed.ttp.psn.internal.PSNTreeNode;
import org.emau.icmvc.ganimed.ttp.psn.model.PSN;
import org.emau.icmvc.ganimed.ttp.psn.model.PSNKey;
import org.emau.icmvc.ganimed.ttp.psn.model.PSNKey_;
import org.emau.icmvc.ganimed.ttp.psn.model.PSNProject;
import org.emau.icmvc.ganimed.ttp.psn.model.PSN_;
import org.jboss.ejb3.annotation.RunAsPrincipal;
import org.jboss.ejb3.annotation.SecurityDomain;

import org.jboss.ws.api.annotation.WebContext;
/**
 * webservice for pseudonyms
 * 
 * @author geidell
 * 
 */
@WebService(name = "gpasService")
@SOAPBinding(style = SOAPBinding.Style.RPC)
@Stateless
@Remote(PSNManager.class)
@PersistenceContext(name = "psn")
@DeclareRoles(value={"Admin","User"})
@SecurityDomain(value="security-beispiel-domain")//simple-auth
@WebContext(authMethod="BASIC", secureWSDLAccess = false)
@PermitAll
@EJB(name="PSN", beanInterface=PSNManager.class)
public class PSNManagerBean implements PSNManager {

	private static final String PSN_NOT_FOUND = "*** PSN NOT FOUND ***";
	private static final String VALUE_NOT_FOUND = "*** VALUE NOT FOUND ***";
	private static final String VALUE_IS_ANONYMISED = "*** VALUE IS ANONYMISED ***";
	private static final Logger logger = Logger.getLogger(PSNManagerBean.class);
	@PersistenceContext
	private EntityManager em;
	private static final Object emSynchronizerDummy = new Object();
	@EJB
	private DomainManagerLocal domainManager;
	private static final int MAX_ATTEMPS_BEFORE_RESEED = 10;
	private static final int MAX_RESEEDS = 5;
	
	@Resource()
	private SessionContext sessionContext = null;

	public SessionContext getSessionContext() {
		return sessionContext;
	}

	public void setSessionContext(SessionContext sessionContext) {
		this.sessionContext = sessionContext;
	}

	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public String getOrCreatePseudonymForVORHER(String value, String domain) throws DBException, InvalidGeneratorException, UnknownDomainException {
		PSN result = null;
		if (logger.isDebugEnabled()) {
			logger.debug("pseudonym requested for value " + value + " within domain " + domain);
		}
		
		if(getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE)!=null && 
				getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE).equals("true")) {
			value=getNewOrigValue(value);
			System.err.println("new value is set for orig value.");
		}

		try {
			result = getPSN(value, domain);
			if (logger.isDebugEnabled()) {
				logger.debug("pseudonym for value '" + value + "' within domain '" + domain + "' found in db");
			}
		} catch (UnknownValueException maybe) {
			if (logger.isDebugEnabled()) {
				logger.debug("pseudonym for value " + value + " within domain " + domain + " not found - generate new");
			}
			PSNProject parent = getPSNProject(domain);
			result = createPSN(parent, value, null);
		}
		return result.getKey().getPseudonym();//getKey() hinzugefügt
	}
	
	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public String getOrCreatePseudonymFor(String value, String domain) throws DBException, InvalidGeneratorException, UnknownDomainException {
		boolean result = false;
		PSN result2 = null;
		if (logger.isDebugEnabled()) {
			logger.debug("pseudonym requested for value " + value + " within domain " + domain);
		}
		
		if(getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE)!=null && 
				getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE).equals("true")) {
			value=getNewOrigValue(value);
			System.err.println("new value is set for orig value.");
		}

		result = getPSNNEW(value, domain);
		if(result==true)
		{
			if (logger.isDebugEnabled()) {
				logger.debug("pseudonym for value '" + value + "' within domain '" + domain + "' found in db");
			}
			try {result2 = getPSN(value, domain);} 
			catch (UnknownValueException e) {
				logger.debug("pseudonym not found although getPSNNEW returned true. Should never happen.");
			}
		}
		if(result==false) {
			if (logger.isDebugEnabled()) {
				logger.debug("pseudonym for value " + value + " within domain " + domain + " not found - generate new");
			}
			PSNProject parent = getPSNProject(domain);
			result2 = createPSN(parent, value, null);

		}
		
		return result2.getKey().getPseudonym();//getKey() hinzugefügt
	}

	/**
	 * Würzburg 2018. Addition
	 * 
	 * Uses AES enryption to encrypt original value.
	 * 
	 * @return encrypted original value.
	 */
	private static String getNewOrigValue(final String value) {
		//StringBuilder newValue=new StringBuilder();
		String newValue=null;
		try {
			newValue=Base64.getEncoder().encodeToString(AESUtil.encrypt(value, AESUtil.secretKey));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if(newValue.equals("") || newValue==null)
			return value+"_!!!";
		return newValue;
	}

	private PSNProject getPSNProject(String domain) throws UnknownDomainException {
		PSNProject parent = em.find(PSNProject.class, domain);
		if (parent == null) {
			String message = "psn-project for domain '" + domain + "' not found";
			logger.error(message);
			throw new UnknownDomainException(message);
		}
		return parent;
	}

	private Generator getGeneratorFor(String domain) throws InvalidGeneratorException, UnknownDomainException {
		try {
			return domainManager.getGeneratorFor(domain);
		} catch (InvalidAlphabetException | InvalidCheckDigitClassException e) {
			String message = "exception while instanciating generator for domain '" + domain + "'";
			logger.fatal(message, e);
			throw new InvalidGeneratorException(message, e);
		}
	}

	/**
	 * 
	 * @param parent
	 * @param value
	 * @param existingPseudonyms
	 *            can be null - check is then performed against the db
	 * @return
	 * @throws DBException
	 * @throws InvalidGeneratorException
	 * @throws UnknownDomainException
	 */
	private PSN createPSN(PSNProject parent, String value, HashSet<String> existingPseudonyms)
			throws DBException, InvalidGeneratorException, UnknownDomainException {
		PSN result;
		// countCollisions - zaehler fuer kollisionen generiertes pseudonym -
		// vorhandene pseudonyme (domain+pseudonym muss unique sein)
		int countCollisions = 0;
		// countReseeds - zaehler fuer generator.randomize() - sonst droht eine
		// endlosschleife
		int countReseeds = 0;
		boolean done = false;
		String pseudonym;
		Generator temp=null;
		Timestamp timestamp = new Timestamp(System.currentTimeMillis());
		logger.error(timestamp);
		synchronized (emSynchronizerDummy) {
			do {
				System.err.println("value @createPSN in PSNMangerBean "+ value);
				if(parent.getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE)!=null && 
						parent.getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE).equals("true") && !value.equals(VALUE_IS_ANONYMISED)) {
					temp=getGeneratorFor(parent.getDomain());				
					temp.setOriginalValue(value);//Verstehe ich nicht mehr... Was soll das? Wegehaupt 2019
					System.err.println("origValue @ createPSN: "+value);
					}
				else {
					temp=getGeneratorFor(parent.getDomain());
				}				
				pseudonym = temp.getNewPseudonym();
				if ((existingPseudonyms != null && existingPseudonyms.contains(pseudonym))					//was ist HashSet<String> existingPseudonyms???
						|| (existingPseudonyms == null && existsPseudonym(parent.getDomain(), pseudonym))) {
					if (logger.isDebugEnabled()) {
						logger.debug("duplicate pseudonym generated - attemp " + countCollisions + " of " + MAX_ATTEMPS_BEFORE_RESEED);
					}
					countCollisions++;
					// sollte zu oft ein schon vorhandener psn generiert worden
					// sein, den generator neu initialisieren
					if (countCollisions > MAX_ATTEMPS_BEFORE_RESEED) {
						countReseeds++;
						if (countReseeds > MAX_RESEEDS) {
							// der generator wurde mehrfach neu initialisiert,
							// abbruch
							String message = "generator reseeded " + MAX_RESEEDS + " times but the generated pseudonym is still duplicate";
							logger.error(message);
							throw new DBException(message);
						}
						countCollisions = 0;
						if (logger.isInfoEnabled()) {
							logger.info("max attemps (" + MAX_ATTEMPS_BEFORE_RESEED + ") for generating a pseudonym expended - reseed the generator");
						}
						getGeneratorFor(parent.getDomain()).randomize();
					}
				} else {
					done = true;
				}
			} while (!done);
			Date now = new Date();      
			Long longTime = now.getTime()/1000;
			if(!value.equals(VALUE_IS_ANONYMISED)) {
				result = new PSN(
						parent, 
						value,
						pseudonym, 
						longTime.longValue(),
						parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)!=null?longTime.longValue()+Long.parseLong(parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)):null);
			}else {
				result = new PSN(
						parent, 
						value,
						pseudonym, 
						longTime.longValue(), 
						null);
			}
			em.persist(result);
			parent.getPsnList().add(result);
		}
		timestamp = new Timestamp(System.currentTimeMillis());
		logger.error(timestamp);
		return result;
	}
	/**
	 * Würzburg 2018. Method was changed.
	 * 
	 * 
	 * @return true if pseudonym exists in relevant domain(s). False otherwise.
	 */
	private boolean existsPseudonym(final String domain, final String pseudonym) {
		
		try {
			if(getPSNProject(domain).getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS)!=null && getPSNProject(domain).getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS).equals("true")) 
			{
				return !getPSNObjectsForUniqueDomains(pseudonym).isEmpty();
			}
			else 
			{
				return !getPSNObjects(domain, pseudonym).isEmpty();
			}
		} catch (UnknownDomainException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return true;
		}
			
	}

	private List<PSN> getPSNObjects(String domain, String pseudonym) {
		Date now = new Date();      
		Long longTime = now.getTime()/1000;
		
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<PSN> criteriaQuery = criteriaBuilder.createQuery(PSN.class);
			Root<PSN> root = criteriaQuery.from(PSN.class);
			Predicate predicate1 = criteriaBuilder.and(criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.pseudonym), pseudonym),//get(PSN_.key).get(PSNKey_.pseudonym) hinzugefügt
													   criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.domain), domain));
			Predicate predicate2 = criteriaBuilder.greaterThan(root.get(PSN_.expiryDate), longTime);//Hinzugefügt Wegehaupt 2018-10	
			Predicate predicate3 = criteriaBuilder.isNull(root.get(PSN_.expiryDate));//Hinzugefügt Wegehaupt 2018-10
			Predicate predicate4 = criteriaBuilder.and(predicate1, criteriaBuilder.or(predicate2,predicate3));//Hinzugefügt Wegehaupt 2018-10
			criteriaQuery.select(root).where(predicate4);//geändert Wegehaupt 2018-10
			return em.createQuery(criteriaQuery).getResultList();
		}
	}
	
	private List<PSN> getPSNObjectsExperimental(String domain, String pseudonym) {
		Date now = new Date();      
		Long longTime = now.getTime()/1000;
		List<PSN> result=null;
		
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<PSN> criteriaQuery = criteriaBuilder.createQuery(PSN.class);
			Root<PSN> root = criteriaQuery.from(PSN.class);
			Predicate predicate1 = criteriaBuilder.and(criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.pseudonym), pseudonym),//get(PSN_.key).get(PSNKey_.pseudonym) hinzugefügt
													   criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.domain), domain));
//			Predicate predicate2 = criteriaBuilder.greaterThan(root.get(PSN_.expiryDate), longTime);//Hinzugefügt Wegehaupt 2018-10	
//			Predicate predicate3 = criteriaBuilder.isNull(root.get(PSN_.expiryDate));//Hinzugefügt Wegehaupt 2018-10
//			Predicate predicate4 = criteriaBuilder.and(predicate1, criteriaBuilder.or(predicate2,predicate3));//Hinzugefügt Wegehaupt 2018-10
			criteriaQuery.select(root).where(predicate1);//geändert Wegehaupt 2018-10
			result=em.createQuery(criteriaQuery).getResultList();
			if(result.size()>1)
			{
				Iterator<PSN> iter = result.iterator();
				while(iter.hasNext()){
					if(iter.next().getExpiryDate()<longTime)
						iter.remove();
				}
			}
				
		}
		return result;
	}
	
	private List<PSN> getAllPSNObjects(String domain) {
		if (logger.isDebugEnabled()) {
			logger.debug("get all entries for domain " + domain);
		}
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<PSN> criteriaQuery = criteriaBuilder.createQuery(PSN.class);
		Root<PSN> root = criteriaQuery.from(PSN.class);
		Predicate predicate = criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.domain), domain);
		criteriaQuery.select(root).where(predicate);
		List<PSN> result = em.createQuery(criteriaQuery).getResultList();
		if (logger.isDebugEnabled()) {
			logger.debug("found " + result.size() + " entries for domain " + domain);
		}
		return result;
	}
	/**
	 * Würzburg 2018. 
	 * 
	 * Iterates over all domains, that have the property MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS set to true.
	 * 
	 * @return list of PSN objects found in relevant domains.
	 */
	private List<PSN> getPSNObjectsForUniqueDomains(String pseudonym) {//what about expiry time? TODO
		if (logger.isDebugEnabled()) {
			logger.debug("get all entries for unique domains ");
		}
		List<DomainLightDTO> localDomainList=domainManager.listDomainsLight();
		
		if (logger.isEnabledFor(Priority.FATAL)) {
			logger.fatal(localDomainList.size()+" domains are tested for ibdw-property");
		}
		
		localDomainList.removeIf(e -> !e.getProperties().contains("MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS=true"));		
		
		List<String> localDomainListString=localDomainList.stream().map(f->f.getDomain()).collect(Collectors.toList());
		//System.err.println(localDomainListString.size()+": "+localDomainListString);
		
		if(localDomainListString.size()==0) {
			if (logger.isEnabledFor(Priority.FATAL)) {
				logger.fatal("something went wrong. Zero domains with MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS=true. ");
			}
		}
		
		List<PSN> result=null;
		
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<PSN> criteriaQuery = criteriaBuilder.createQuery(PSN.class);
			Root<PSN> root = criteriaQuery.from(PSN.class);
			
			Expression<PSNProject> parentExpression = root.get(PSN_.psnProject);
			
			Predicate predicate1 = parentExpression.in(localDomainListString);
			Predicate predicate2 = criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.pseudonym),pseudonym);//vorher root.get(PSN_.pseudonym)
			System.err.println("pseudonym="+pseudonym);
			Predicate predicate3=criteriaBuilder.and(predicate1, predicate2);
					
			criteriaQuery.select(root).where(predicate3);
			result = em.createQuery(criteriaQuery).getResultList();
			System.err.println("number of results in unique domains: "+result.size() );
		}
		return result;
	}

	private List<PSN> getAllPSNObjectsForValuePrefix(String domain, String valuePrefix) {
		if (logger.isDebugEnabled()) {
			logger.debug("get all entries for domain '" + domain + "' where the value starts with '" + valuePrefix + "'");
		}
		CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
		CriteriaQuery<PSN> criteriaQuery = criteriaBuilder.createQuery(PSN.class);
		Root<PSN> root = criteriaQuery.from(PSN.class);
		Predicate predicate = criteriaBuilder.and(criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.domain), domain),
				criteriaBuilder.like(root.get(PSN_.key).get(PSNKey_.originalValue), valuePrefix + '%'));
		criteriaQuery.select(root).where(predicate);
		List<PSN> result = em.createQuery(criteriaQuery).getResultList();
		if (logger.isDebugEnabled()) {
			logger.debug("found " + result.size() + " entries for domain '" + domain + "' where the value starts with '" + valuePrefix + "'");
		}
		return result;
	}

	@Override
	public String getPseudonymFor(String value, String domain) throws UnknownValueException {
		if (logger.isDebugEnabled()) {
			logger.debug("pseudonym requested for value " + value + " within domain " + domain);
		}
		//Addition Wegehaupt 2018
		try {
			if(getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE)!=null && 
					getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE).equals("true")) {
				value=getNewOrigValue(value);
			}
		} catch (UnknownDomainException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		PSN result = getPSN(value, domain);
		return result.getKey().getPseudonym();//getKey() hinzugefügt
	}

	private PSN getPSN(String value, String domain) throws UnknownValueException {		//vorher private PSN getPSN(String value, String domain) throws UnknownValueException
		// zusammengesetzter primary key
		
		PSN result = null;//vorher PSN result = null;
		PSNKey key = new PSNKey(value, domain,"");//stimmt das so?
		
//		try {
//			if(getPSNProject(domain).getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS)!=null && 
//					getPSNProject(domain).getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS).equals("true")) {
//				result = findKeyforUniqueDomain(key);							
//			}
//			else {
				result = findKeyforNotUniqueDomain(key);//vorher result = findKeyforNotUniqueDomain(key);
//			}
//		} catch (UnknownDomainException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		if (result == null) { //vorher: if (result == null)
			String message = "value '" + value + "' for domain '" + domain + "' not found";
			logger.error(message);
			throw new UnknownValueException(message);
		}
		return result;
	}

	private boolean getPSNNEW(String value, String domain) {
		
		boolean result = false;
		PSNKey key = new PSNKey(value, domain,"");
		
		result = isExistsKeyforNotUniqueDomain(key);
		
		if (result == false) {
			String message = "value '" + value + "' for domain '" + domain + "' not found";
			logger.error(message);
		}
		return result;
	}
	
	@Override
	public void anonymiseEntry(String value, String domain) throws DBException, UnknownValueException, ValueIsAnonymisedException {
		if (logger.isDebugEnabled()) {
			logger.debug("anonymising a pseudonym for domain '" + domain + "'");
		}
		if (AnonymDomain.NAME.equals(domain)) {
			logger.warn("it's not possible to anonymise values for the intern domain '" + AnonymDomain.NAME + "'");
			return;
		}
		if (isAnonymised(value)) {
			String message = "value " + value + " is already anonymised";
			logger.info(message);
			throw new ValueIsAnonymisedException(message);
		}
		synchronized (emSynchronizerDummy) {
			PSN origEntity = getPSN(value, domain);
			if (origEntity != null) {
				try {
					String anonym = getOrCreatePseudonymFor(domain + AnonymDomain.DELIMITER + origEntity.getKey().getPseudonym(), AnonymDomain.NAME);//getKey() hinzugefügt

					PSNProject parent = origEntity.getPSNProject();
					em.remove(origEntity);
					parent.getPsnList().remove(origEntity);
					em.flush();

					insertValuePseudonymPair(anonym, origEntity.getKey().getPseudonym(), parent.getDomain());//getKey() hinzugefügt

					if (logger.isInfoEnabled()) {
						logger.info("pseudonym '" + origEntity.getKey().getPseudonym() + "' within domain '" + domain + "' anonymised");//getKey() hinzugefügt
					}
				} catch (Exception e) {
					logger.error("error while anonymising psn entry", e);
					throw new DBException(e);
				}
			} else {
				String message = "pseudonym for value '" + value + "' not found within domain '" + domain + "'";
				logger.warn(message);
				throw new DBException(message);
			}
		}
	}
	
	@Override
	public void newAnonymIBDW(String domain) throws DBException {
		if (logger.isDebugEnabled()) {
			logger.debug("adding an anonym for domain '" + domain + "'");
		}
		if (AnonymDomain.NAME.equals(domain)) {
			logger.warn("it's not possible to anonymise values for the intern domain '" + AnonymDomain.NAME + "'");
			return;
		}		
		synchronized (emSynchronizerDummy) {
			try {
				PSNProject project = getPSNProject(domain);
				PSN anonym = createPSN(project,VALUE_IS_ANONYMISED, null);

				if (logger.isInfoEnabled()) {
					logger.info(anonym.getKey().getPseudonym() + "' within domain '" + domain + "' added");
				}
			} catch (Exception e) {
				logger.error("error while adding an anonym", e);
				throw new DBException(e);
			}
		}
	}

	@Override
	public void deleteEntry(String value, String domain) throws DeletionForbiddenException, UnknownDomainException, UnknownValueException {
		if (logger.isDebugEnabled()) {
			logger.debug("removing value-pseudonym-pair for value '" + value + "' from domain '" + domain + "'");
		}
		if(getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE)!=null && 
				getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE).equals("true")) {
			value=getNewOrigValue(value);
		}
		if (!deletablePSNsForDomain(domain)) {
			String message = "the domain '" + domain + "' does not allow deletion of value-pseudonym-pairs";
			logger.warn(message);
			throw new DeletionForbiddenException(message);
		} else {
			PSN psn = getPSN(value, domain);
			synchronized (emSynchronizerDummy) {
				psn.getPSNProject().getPsnList().remove(psn);
				em.remove(psn);
			}
		}
		logger.warn("value-pseudonym-pair for value '" + value + "' removed from domain '" + domain + "'");
	}

	private boolean deletablePSNsForDomain(String domain) throws UnknownDomainException {
		PSNProject project = getPSNProject(domain);
		String property = project.getProperties().getOrDefault(GeneratorProperties.PSNS_DELETABLE, "");
		return "true".equalsIgnoreCase(property);
	}

	@Override
	public void validatePSN(String psn, String domain) throws InvalidPSNException, InvalidGeneratorException, UnknownDomainException {
		if (logger.isDebugEnabled()) {
			logger.debug("validate pseudonym '" + psn + "' within domain '" + domain + "'");
		}
		try {
			getGeneratorFor(domain).check(psn);
		} catch (CharNotInAlphabetException e) {
			throw new InvalidPSNException(e);
		}
	}

	@Override
	public String getValueFor(String psn, String domain)
			throws InvalidPSNException, PSNNotFoundException, InvalidGeneratorException, UnknownDomainException, ValueIsAnonymisedException {
		String result = "";
		if (logger.isDebugEnabled()) {
			logger.debug("find value for pseudonym '" + psn + "' within domain '" + domain + "'");
		}
		validatePSN(psn, domain);
		List<PSN> resultList = getPSNObjects(domain, psn);
		if (resultList.size() == 1) {
			result = resultList.get(0).getKey().getOriginValue();
		} else if (resultList.isEmpty()) {
			String message = "value for pseudonym '" + psn + "' not found within domain '" + domain + "'";
			logger.warn(message);
			throw new PSNNotFoundException(message);
		} else {
			String message = "found multiple values for pseudonym '" + psn + "' within domain '" + domain + "' - may be a jpa-caching problem";
			logger.fatal(message);
			throw new InvalidPSNException(message);
		}
		if (isAnonymised(result)) {
			String message = "requested value for pseudonym " + psn + " can't be retrieved - it is anonymised";
			logger.info(message);
			throw new ValueIsAnonymisedException(message);
		}
		return result;
	}
	
	@Override
	public String getExpiry(String psn, String domain)
			throws InvalidPSNException, PSNNotFoundException, InvalidGeneratorException, UnknownDomainException {
		String result = "";
		if (logger.isDebugEnabled()) {
			logger.debug("find expiryDate for pseudonym '" + psn + "' within domain '" + domain + "'");
		}
		validatePSN(psn, domain);
		List<PSN> resultList = getPSNObjects(domain, psn);
		if (resultList.size() == 1) {
			result = resultList.get(0).toPSNDTO().getExpiryDateString();
		} else if (resultList.isEmpty()) {
			String message = "value for pseudonym '" + psn + "' not found within domain '" + domain + "'";
			logger.warn(message);
			throw new PSNNotFoundException(message);
		} else {
			String message = "found multiple values for pseudonym '" + psn + "' within domain '" + domain + "' - may be a jpa-caching problem";
			logger.fatal(message);
			throw new InvalidPSNException(message);
		}
		return result;
	}
	
	private PSN getValueForAsPSN(String psn, String domain)
			throws InvalidPSNException, PSNNotFoundException, InvalidGeneratorException, UnknownDomainException, ValueIsAnonymisedException {
		PSN result = null;
		if (logger.isDebugEnabled()) {
			logger.debug("find value for pseudonym '" + psn + "' within domain '" + domain + "'");
		}
		validatePSN(psn, domain);
		List<PSN> resultList = getPSNObjects(domain, psn);
		if (resultList.size() == 1) {
			result = resultList.get(0);
		} else if (resultList.isEmpty()) {
			String message = "value for pseudonym '" + psn + "' not found within domain '" + domain + "'";
			logger.warn(message);
			throw new PSNNotFoundException(message);
		} else {
			String message = "found multiple values for pseudonym '" + psn + "' within domain '" + domain + "' - may be a jpa-caching problem";
			logger.fatal(message);
			throw new InvalidPSNException(message);
		}
		if (isAnonymised(result.getKey().getOriginValue())) {
			String message = "requested value for pseudonym " + psn + " can't be retrieved - it is anonymised";
			logger.info(message);
			throw new ValueIsAnonymisedException(message);
		}
		return result;
	}
	
	
	
	/**
	 * Würzburg 2018. 
	 * 
	 * @return decoded original value for given pseudonym
	 */
	@Override
	@RolesAllowed("Admin")
	public String getValueForDecode(String psn, String domain)
			throws InvalidPSNException, PSNNotFoundException, InvalidGeneratorException, UnknownDomainException, ValueIsAnonymisedException {
		String result = "";
		logger.info ("Caller: '" + this.sessionContext.getCallerPrincipal().getName() +"'");
		if (logger.isDebugEnabled()) {
			logger.debug("find value for pseudonym '" + psn + "' within domain '" + domain + "'");
		}
		validatePSN(psn, domain);
		List<PSN> resultList = getPSNObjects(domain, psn);
		if (resultList.size() == 1) {
			result = resultList.get(0).getKey().getOriginValue();
			try {
				result = AESUtil.decrypt(result, AESUtil.secretKey);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else if (resultList.isEmpty()) {
			String message = "value for pseudonym '" + psn + "' not found within domain '" + domain + "'";
			logger.warn(message);
			throw new PSNNotFoundException(message);
		} else {
			String message = "found multiple values for pseudonym '" + psn + "' within domain '" + domain + "' - may be a jpa-caching problem";
			logger.fatal(message);
			throw new InvalidPSNException(message);
		}
		if (isAnonymised(result)) {
			String message = "requested value for pseudonym " + psn + " can't be retrieved - it is anonymised";
			logger.info(message);
			throw new ValueIsAnonymisedException(message);
		}
		return result;
	}

	private boolean isAnonymised(String value) {
		return value.startsWith(AnonymDomain.PREFIX) && value.endsWith(AnonymDomain.SUFFIX);
	}

	@Override
	public HashMapWrapper<String, String> getOrCreatePseudonymForList(Set<String> values, String domain)
			throws DBException, InvalidGeneratorException, UnknownDomainException {
		if (values == null) {
			logger.warn("parameter 'values' must not be null");
			values = new HashSet<String>();
		}
		if (logger.isInfoEnabled()) {
			logger.info("get or create pseudonyms for " + values.size() + " values within domain '" + domain + "'");
		}
		//Hier müssten ggf. die Originalwerte verschlüsselt werden. Was passiert mit der zurückgegbenen HashMap??? TODO
		HashMap<String, String> result = new HashMap<String, String>((int) Math.ceil(values.size() / 0.75));
		if (values.size() < 100) {
			// wenig eintraege - einzeln generieren
			for (String value : values) {				
				result.put(value, getOrCreatePseudonymFor(value, domain));//Hier wird ggf. bereits verschlüsselt...
			}
		} else {
			// viele eintraege - alle holen und cachen
			if (logger.isDebugEnabled()) {
				logger.debug("many entries requested - using cache");
			}
			PSNProject parent = getPSNProject(domain);
			List<PSN> psns = parent.getPsnList();
			// genug platz, damit kein rehash passiert
			HashSet<String> allPseudonyms = new HashSet<String>((int) Math.ceil((psns.size() + values.size()) / 0.75));
			HashMap<String, String> valuePsnMap = new HashMap<String, String>((int) Math.ceil((psns.size() + values.size()) / 0.75));
			for (PSN psn : psns) {
				valuePsnMap.put(psn.getKey().getOriginValue(), psn.getKey().getPseudonym());//getKey() hinzugefügt
				allPseudonyms.add(psn.getKey().getPseudonym());//getKey() hinzugefügt
			}
			int count = 0;
			int countForBeep = values.size() / 50;
			int beepNumber = 1;
			for (String value : values) {
				String pseudonym = valuePsnMap.get(value);
				if (pseudonym != null) {
					result.put(value, pseudonym);
				} else {
					pseudonym = createPSN(parent, value, allPseudonyms).getKey().getPseudonym();//getKey() hinzugefügt Hier wird ggf. bereits verschlüsselt.
					result.put(value, pseudonym);
					valuePsnMap.put(value, pseudonym);
					allPseudonyms.add(pseudonym);
				}
				count++;
				if (count == countForBeep) {
					if (logger.isInfoEnabled()) {
						logger.info("proceeded " + beepNumber * count + " of " + values.size() + " values");
					}
					beepNumber++;
					count = 0;
				}
			}
		}
		return new HashMapWrapper<String, String>(result);
	}

	@Override
	public HashMapWrapper<String, String> getValueForList(Set<String> psnList, String domain)
			throws InvalidGeneratorException, InvalidPSNException, UnknownDomainException {
		if (psnList == null) {
			logger.warn("parameter 'psnList' must not be null");
			psnList = new HashSet<String>();
		}
		if (logger.isDebugEnabled()) {
			logger.debug("get original values for " + psnList.size() + " pseudonyms within domain '" + domain + "'");
		}
		HashMap<String, String> result = new HashMap<String, String>((int) Math.ceil(psnList.size() / 0.75));
		if (psnList.size() < 100) {
			// wenig eintraege - einzeln holen
			for (String pseudonym : psnList) {
				try {
					result.put(pseudonym, getValueFor(pseudonym, domain));
				} catch (PSNNotFoundException e) {
					result.put(pseudonym, PSN_NOT_FOUND);
				} catch (ValueIsAnonymisedException e) {
					result.put(pseudonym, VALUE_IS_ANONYMISED);
				}
			}
		} else {
			// viele eintraege - alle holen und cachen
			if (logger.isDebugEnabled()) {
				logger.debug("many entries requested - using cache");
			}
			List<PSN> psns = getAllPSNObjects(domain);
			// genug platz, damit kein rehash passiert
			HashMap<String, String> psnValueMap = new HashMap<String, String>((int) Math.ceil(psns.size() / 0.75));
			for (PSN psn : psns) {
				psnValueMap.put(psn.getKey().getPseudonym(), psn.getKey().getOriginValue());//getKey() hinzugefügt
			}
			for (String pseudonym : psnList) {
				String value = psnValueMap.get(pseudonym);
				if (value == null) {
					logger.warn("value for pseudonym '" + pseudonym + "' not found within domain '" + domain + "'");
					result.put(pseudonym, PSN_NOT_FOUND);
				} else if (isAnonymised(value)) {
					if (logger.isInfoEnabled()) {
						logger.info("requested value for pseudonym " + pseudonym + " can't be retrieved - it is anonymised");
					}
					result.put(pseudonym, VALUE_IS_ANONYMISED);
				} else {
					result.put(pseudonym, value);
				}
			}
		}
		return new HashMapWrapper<String, String>(result);
	}

	@Override
	public HashMapWrapper<String, String> getPseudonymForList(Set<String> values, String domain) {
		if (values == null) {
			logger.warn("parameter 'psnList' must not be null");
			values = new HashSet<String>();
		}
		if (logger.isInfoEnabled()) {
			logger.info("get pseudonyms for " + values.size() + " values within domain '" + domain + "'");
		}
		HashMap<String, String> result = new HashMap<String, String>((int) Math.ceil(values.size() / 0.75));
		if (values.size() < 100) {
			for (String value : values) {
				try {
					result.put(value, getPseudonymFor(value, domain));
				} catch (UnknownValueException e) {
					result.put(value, VALUE_NOT_FOUND);
				}
			}
		} else {
			// viele eintraege - alle holen und cachen
			if (logger.isDebugEnabled()) {
				logger.debug("many entries requested - using cache");
			}
			List<PSN> psns = getAllPSNObjects(domain);
			// genug platz, damit kein rehash passiert
			HashMap<String, String> valuePsnMap = new HashMap<String, String>((int) Math.ceil(psns.size() / 0.75));
			for (PSN psn : psns) {
				valuePsnMap.put(psn.getKey().getOriginValue(), psn.getKey().getPseudonym());//getKey() hinzugefügt
			}
			for (String value : values) {
				String pseudonym = valuePsnMap.get(value);
				if (pseudonym == null) {
					logger.warn("pseudonym for value '" + value + "' not found within domain '" + domain + "'");
					result.put(value, VALUE_NOT_FOUND);
				} else {
					result.put(value, pseudonym);
				}
			}
		}
		return new HashMapWrapper<String, String>(result);
	}

	@Override
	public HashMapWrapper<String, String> getPseudonymForValuePrefix(String valuePrefix, String domain) {
		if (logger.isInfoEnabled()) {
			logger.info("get pseudonyms for values which starts with '" + valuePrefix + "' within domain '" + domain + "'");
		}
		HashMap<String, String> result = new HashMap<String, String>();
		List<PSN> psnList = getAllPSNObjectsForValuePrefix(domain, valuePrefix);
		for (PSN psn : psnList) {
			result.put(psn.getKey().getOriginValue(), psn.getKey().getPseudonym());//getKey() hinzugefügt
		}
		return new HashMapWrapper<String, String>(result);
	}

	@Override
	public void insertValuePseudonymPair(String value, String pseudonym, String domain)
			throws DBException, InvalidGeneratorException, InvalidPSNException, UnknownDomainException {
		
		boolean isUniqueDomain=false;
		boolean isExpiryDomain=false;
		
		if (logger.isInfoEnabled()) {
			logger.info("insert pseudonym for '" + value + "' in domain '" + domain + "'");
		}
		PSNProject parent = getPSNProject(domain);
		validatePSN(pseudonym, domain);
		if(getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE)!=null && 
				getPSNProject(domain).getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE).equals("true")) {
			value=getNewOrigValue(value);
		}
		if(getPSNProject(domain).getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS)!=null && 
				getPSNProject(domain).getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS).equals("true")) {
			isUniqueDomain=true;							
		}
		if(getPSNProject(domain).getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)!=null && 
				!getPSNProject(domain).getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN).equals("")) {
			isExpiryDomain=true;							
		}
		PSNKey key = new PSNKey(value, domain,"");//stimmt das so?
		PSN psn=null;
		
//		if(isUniqueDomain) {	//new Wegehaupt 2018
//			psn=findKeyforUniqueDomain(key);}
//		else {
			psn = findKeyforNotUniqueDomain(key);
//		}
		
		//PSN psn = em.find(PSN.class, key);
		
		if (psn != null) {
			if (psn.getKey().getPseudonym().equals(pseudonym)) {//getKey() hinzugefügt
				logger.warn("pseudonym for value '" + value + "' already exists within domain '" + domain + "'");
				return;
			} else {
				String message = "a different pseudonym for value '" + value + "' already exists within domain '" + domain + "'";
				logger.error(message);
				throw new DBException(message);
			}
		} else if (existsPseudonym(domain, pseudonym)) {
			// erst nach der pruefung auf value, da nur eine warnung
			// kommen soll, wenn das paar genau so schon exisitert
			String message = "pseudonym '" + pseudonym + "' already exists within domain '" + domain + "'";
			logger.error(message);
			throw new DBException(message);
		}
		synchronized (emSynchronizerDummy) {
			//psn = new PSN(parent, value, pseudonym);
			Date now = new Date();      
			Long longTime = now.getTime()/1000;
			psn = new PSN(
					parent, 
					value,
					pseudonym, 
					longTime.longValue(), 
					parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)!=null?longTime.longValue()+Long.parseLong(parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)):null);
			
			em.persist(psn);
			parent.getPsnList().add(psn);
		}
		if (logger.isInfoEnabled()) {
			logger.info("pseudonym (or anonym) for '" + value + "' in domain '" + domain + "' inserted");
		}
	}

	//This method is (also) used by the frontend when inserting just ONE pair.
	//Changed Würzburg 2018
	@Override
	public void insertValuePseudonymPairs(HashMapWrapper<String, String> pairs, String domain)
			throws DBException, InvalidGeneratorException, InvalidPSNException, UnknownDomainException {
		boolean exchangeOrigValue=false;
		boolean isUniqueDomain=false;
		if (pairs == null) {
			logger.warn("parameter 'pairs' should not be null");
			pairs = new HashMapWrapper<String, String>();
		}
		if (logger.isInfoEnabled()) {
			logger.info("insert " + pairs.getMap().size() + " values-pseudonym pairs in domain '" + domain + "'");
		}
		PSNProject parent = getPSNProject(domain);
		
		if(parent.getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE)!=null && 
				parent.getProperties().get(GeneratorProperties.ENCODE_ORIGINAL_VALUE).equals("true")) {
			exchangeOrigValue=true;
		}
		if(parent.getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS)!=null && 
				parent.getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS).equals("true")) {
			isUniqueDomain=true;
		}
		
		synchronized (emSynchronizerDummy) {
			List<String> duplicates = new ArrayList<String>();
			for (Entry<String, String> entry : pairs.getMap().entrySet()) {
				validatePSN(entry.getValue(), domain);
				PSNKey key=null;
				PSN psn=null;
				if(exchangeOrigValue) {		//new Wegehaupt 2018
					key = new PSNKey(getNewOrigValue(entry.getKey()), domain,"");}//stimmt das so?
				else {
					key = new PSNKey(entry.getKey(), domain,"");}//stimmt das so?
				if(isUniqueDomain) {	//new Wegehaupt 2018
					psn = findKeyforUniqueDomain(key);}//////////////////////////////////////////////////////TODO???
				else {
					psn = findKeyforNotUniqueDomain(key);}
				
				if (psn != null) {
					if (psn.getKey().getPseudonym().equals(entry.getValue())) {//getKey() hinzugefügt
						logger.warn("pseudonym for value '" + entry.getKey() + "' already exists within domain '" + domain + "'");
						duplicates.add(entry.getKey());
					} else {
						String message = "a different pseudonym for value '" + entry.getKey() + "' already exists within domain '" + psn.getPSNProject().getDomain() + "'";
						logger.error(message);
						throw new DBException(message);
					}
				} else if (existsPseudonym(domain, entry.getValue())) {
					// erst nach der pruefung auf value, da nur eine warnung
					// kommen soll, wenn das paar genau so schon exisitert
					String message = "pseudonym '" + entry.getValue() + "' already exists within domain '" + domain + "'";
					logger.error(message);
					throw new DBException(message);
				}
			}
			for (String duplicate : duplicates) {
				pairs.getMap().remove(duplicate);
			}
			synchronized (emSynchronizerDummy) {
				for (Entry<String, String> entry : pairs.getMap().entrySet()) {
					PSN psn=null;
					
					Date now = new Date();      
					Long longTime = now.getTime()/1000;					
					
					if(exchangeOrigValue) {
						psn = new PSN(parent, getNewOrigValue(entry.getKey()), entry.getValue(),longTime.longValue(),parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)!=null?longTime.longValue()+Long.parseLong(parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)):null);}//changed Wegehaupt 2018
					else {
						psn = new PSN(parent, entry.getKey(), entry.getValue(),longTime.longValue(),parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)!=null?longTime.longValue()+Long.parseLong(parent.getProperties().get(GeneratorProperties.EXPIRY_TIME_OF_PSN)):null);}//changed Wegehaupt 2018
					em.persist(psn);
					parent.getPsnList().add(psn);
				}
			}
		}
		if (logger.isInfoEnabled()) {
			logger.info("inserted " + pairs.getMap().size() + " values-pseudonym pairs in domain '" + domain + "'");
		}
	}

	
	
	private PSN findKeyforUniqueDomain(PSNKey key) {
		String origValue=key.getOriginValue();
		List<DomainLightDTO> localDomainList=domainManager.listDomainsLight();		
		//localDomainList.removeIf(e -> !(getPSNProject(e.getDomain()).getDomain().getProperties().containsKey(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS) && getPSNProject(e.getDomain()).getDomain().getProperties().get(GeneratorProperties.MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS).equals("true")));
		localDomainList.removeIf(e -> !e.getProperties().contains("MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS=true"));

		if(localDomainList.size()==0) {
			if (logger.isEnabledFor(Priority.FATAL)) {
				logger.fatal("Something went wrong. Zero domains with property MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS=true. ");
			}
			System.err.println("Something went wrong. Zero domains with property MEMBER_OF_DOMAINS_WITH_UNIQUE_PSNS=true. ");
		}
		List<String> localDomainListString=localDomainList.stream().map(f->f.getDomain()).collect(Collectors.toList());
		
		PSN result=null;
		
		for(String uniqueDomain:localDomainListString) {
			key = new PSNKey(origValue, uniqueDomain,"");//stimmt das so?
			result = findKeyforNotUniqueDomain(key);
			if(result!=null)
				break;
		}
		return result;
	}
	
	private PSN findKeyforNotUniqueDomain(PSNKey key) {

		PSN result=null;
		Date now = new Date(); 
		Long longTime = now.getTime()/1000;
		
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<PSN> criteriaQuery = criteriaBuilder.createQuery(PSN.class);
						
			Root<PSN> root = criteriaQuery.from(PSN.class);
			Predicate predicate1 = criteriaBuilder.and(criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.domain), key.getDomain()),
														criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.originalValue), key.getOriginValue()));//stimmt das?
			Predicate predicate2 = criteriaBuilder.greaterThan(root.get(PSN_.expiryDate), longTime);
			Predicate predicate3 = criteriaBuilder.isNull(root.get(PSN_.expiryDate));
			Predicate predicate4 = criteriaBuilder.and(predicate1, criteriaBuilder.or(predicate2,predicate3));
			criteriaQuery.select(root).where(predicate4);
			try{
				result=em.createQuery(criteriaQuery).getSingleResult();
			} catch(NoResultException e) {
				//e.printStackTrace();
				System.err.println("No Key found. All good.");
			}
		}
		return result!=null?result:null;		
	}
	
	private boolean isExistsKeyforNotUniqueDomain(PSNKey key) {

		Long result=null;
		Date now = new Date(); 
		Long longTime = now.getTime()/1000;
		
		synchronized (emSynchronizerDummy) {
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<Long> criteriaQuery = criteriaBuilder.createQuery(Long.class);
			
			Root<PSN> root=criteriaQuery.from(PSN.class);
			Expression<Long> exp = criteriaBuilder.count(root);
			Predicate predicate1 = criteriaBuilder.and(criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.domain), key.getDomain()),
														criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.originalValue), key.getOriginValue()));//stimmt das?
			Predicate predicate2 = criteriaBuilder.greaterThan(root.get(PSN_.expiryDate), longTime);
			Predicate predicate3 = criteriaBuilder.isNull(root.get(PSN_.expiryDate));
			Predicate predicate4 = criteriaBuilder.and(predicate1, criteriaBuilder.or(predicate2,predicate3));
			criteriaQuery.select(exp).where(predicate4);
			try{
				result=em.createQuery(criteriaQuery).getSingleResult();
			} catch(NoResultException e) {
				//e.printStackTrace();
				System.err.println("No Key found. All good.");
			}
		}
		return result > 0L;
	}

	@Override
	public PSNTreeDTO getPSNTreeForPSN(String psn, String domain) throws DBException, UnknownDomainException, InvalidPSNException,
			PSNNotFoundException, InvalidGeneratorException, ValueIsAnonymisedException {
		PSNProject currentProject = getPSNProject(domain);
//		String currentPSN = psn;
		PSN currentPSN = getValueForAsPSN(psn, currentProject.getDomain());

		// Zum Root Projekt zurueckiterieren
		while (currentProject.getParent() != null) {
//			currentPSN = getValueFor(currentPSN, currentProject.getDomain());
			currentPSN = getValueForAsPSN(currentPSN.getKey().getPseudonym(), currentProject.getDomain());	//neu
			currentProject = getPSNProject(currentProject.getParent().getDomain());
		}
		// Initiales hinzufuegen des Root Nodes. Bei diesem wird der originalValue des aktuellen Projektes verwendet und nicht das Pseudonym		
//		PSNTreeNode rootNode = new PSNTreeNode("ROOT", getValueFor(currentPSN, currentProject.getDomain()));
//		rootNode.getChildren().add(createPSNTree(currentPSN, currentProject));
		PSNTreeNode rootNode = new PSNTreeNode("ROOT", currentPSN.getKey().getOriginValue(),currentPSN.getCreatedDate(), currentPSN.getExpiryDate());
		rootNode.getChildren().add(createPSNTreeFromPSN(currentPSN, currentProject));//vorher createPSNTree(..)
		
		return rootNode.toDTO();
	}

	/**
	 * Recursively traverse deeper into psn_projects until all projects related to the passed originalValue and project are found
	 * 
	 * @return a PSNTreeNode containing child nodes, child child nodes and so on
	 */
	private PSNTreeNode createPSNTree(String originalValue, PSNProject project) {
		PSNTreeNode currentNode = new PSNTreeNode(project.getDomain(), originalValue,null,null);//added null, null 
		for (PSNProject child : project.getChildren()) {
			try {
				String nextPSN = getPseudonymFor(originalValue, child.getDomain());
				currentNode.getChildren().add(createPSNTree(nextPSN, child));
			} catch (UnknownValueException e) {
				logger.warn("Unexpected exception: no pseudonym available in domain: " + child.getDomain() + " for originalValue: " + originalValue);
			}
		}
		return currentNode;
	}
	
	private PSNTreeNode createPSNTreeFromPSN(PSN originalValue, PSNProject project) {
		PSNTreeNode currentNode = new PSNTreeNode(project.getDomain(), originalValue.getKey().getOriginValue(),originalValue.getCreatedDate(),originalValue.getExpiryDate());
		for (PSNProject child : project.getChildren()) {
			try {
				PSN nextPSN = getValueForAsPSN(originalValue.getKey().getOriginValue(), child.getDomain());
				currentNode.getChildren().add(createPSNTreeFromPSN(nextPSN, child));
			} catch (Exception e) {
				logger.warn("Unexpected exception: no pseudonym available in domain: " + child.getDomain() + " for originalValue: " + originalValue);
			}
		}
		return currentNode;
	}

	/**
	 * Würzburg 2018. 
	 * 
	 * @return domain(s) of given pseudonym
	 */
	@Override
	public String getPSNDomain(String psn) throws DBException, InvalidGeneratorException, InvalidPSNException,
			PSNNotFoundException, ValueIsAnonymisedException {
		
			CriteriaBuilder criteriaBuilder = em.getCriteriaBuilder();
			CriteriaQuery<PSN> criteriaQuery = criteriaBuilder.createQuery(PSN.class);
			Root<PSN> root = criteriaQuery.from(PSN.class);
			Predicate predicate = criteriaBuilder.equal(root.get(PSN_.key).get(PSNKey_.pseudonym), psn);//vorher get(PSN_.pseudonym)
			criteriaQuery.select(root).where(predicate);

			List<PSN> domains=null;
			StringBuilder returnString=new StringBuilder();

			domains=em.createQuery(criteriaQuery).getResultList();
			if(domains!=null) {
				for(PSN d:domains) {
					returnString.append(d.getPSNProject().getDomain());
					returnString.append(", ");
				}
			}
			return returnString.toString().length() > 0 ? returnString.toString().substring(0, returnString.toString().length() - 2): "";
			
	}

	
	//TODO, method not used.
	@Override
	public Boolean isPSNExpired(String psn, String domain) throws InvalidGeneratorException, InvalidPSNException,
			PSNNotFoundException, UnknownDomainException, ValueIsAnonymisedException {
		
		Date now = new Date();      
		Long longTime = now.getTime()/1000;
		
		PSN result = null;
		PSNKey key = new PSNKey(psn, domain,"");//stimmt das so?
		result=findKeyforUniqueDomain(key);
		if(longTime>result.getExpiryDate())
			return true;
		return false;
	}
}
