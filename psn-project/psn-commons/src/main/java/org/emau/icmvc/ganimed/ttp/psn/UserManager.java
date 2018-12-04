package org.emau.icmvc.ganimed.ttp.psn;

import java.util.HashMap;
import java.util.List;

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

import javax.jws.WebParam;
import javax.jws.WebService;
import javax.xml.bind.annotation.XmlElement;

import org.emau.icmvc.ganimed.ttp.psn.exceptions.DBException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidGeneratorException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.InvalidUserNameException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownDomainException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownUserException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UnknownValueException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.UserAlreadyExistsException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.ValueIsAnonymisedException;
import org.emau.icmvc.ganimed.ttp.psn.exceptions.WrongPasswordException;

@WebService
public interface UserManager {

	
	/**
	 * creates a new user
	 * 
	 * @param username & password
	 * 
	 * @throws InvalidUserNameException
	 *             if the given domain name is invalid (null or empty)
	 */
	public void addUser(@XmlElement(required = true) @WebParam(name = "user") String user, 
						@XmlElement(required = true) @WebParam(name = "password") String password) 
								throws InvalidUserNameException, UserAlreadyExistsException;

	/**
	 * deletes the given user
	 * 
	 * @param domain
	 *            identifier
   	 * @throws InvalidUserNameException
     				if the given user name is invalid (null or empty)
	 * @throws UnknownUserException
	 *             if the given user is not found
	 */
	
	public void deleteUser(@XmlElement(required = true) @WebParam(name = "user") String user,
			@XmlElement(required = true) @WebParam(name = "password") String password)
								throws InvalidUserNameException, UnknownUserException;
	
	public void deleteUserAsAdmin(@XmlElement(required = true) @WebParam(name = "user") String user)
								throws InvalidUserNameException, UnknownUserException;	
	
	public @XmlElement(required = true) String findUser(@XmlElement(required = true) @WebParam(name = "username") String username, 
							@XmlElement(required = true) @WebParam(name = "password") String password)
								throws InvalidUserNameException, UnknownUserException, WrongPasswordException;	

	public @XmlElement(required = true) String findUserByName(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException, UnknownUserException;	

	public void setVerified(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException, UnknownUserException;
	
	public void setUnverified(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException, UnknownUserException;

	public void setAdmin(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException, UnknownUserException;

	public void setNotAdmin(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException, UnknownUserException;

	
	public @XmlElement(required = true) Boolean isAdmin(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException, UnknownUserException;	

	public @XmlElement(required = true) Boolean isVerified(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException, UnknownUserException;	
	
	public @XmlElement(required = true) List<String> getRoles(@XmlElement(required = true) @WebParam(name = "username") String username)
			throws InvalidUserNameException, UnknownUserException;
	
	public @XmlElement(required = true) Boolean hasRole(@XmlElement(required = true) @WebParam(name = "username") String username,
			@XmlElement(required = true) @WebParam(name = "role") String role)
			throws InvalidUserNameException, UnknownUserException;
	
	public void toggleRole(@XmlElement(required = true) @WebParam(name = "username") String username,
			@XmlElement(required = true) @WebParam(name = "role") String role)
			throws InvalidUserNameException, UnknownUserException;	

	public @XmlElement(required = true) List<String> getAllRoles();
	
	
	/**
	 * returns all users
	 * 
	 * @return see List<String>
	 * 
	 */
	
	public @XmlElement(required = true) HashMap<Long,String> listUsers();

	public void checkUserName(@XmlElement(required = true) @WebParam(name = "username") String username)
								throws InvalidUserNameException;
	
	public void loginForSOAP()
								throws InvalidUserNameException, WrongPasswordException;
	
	public @XmlElement(required = true) boolean isLoggedIn();

	public void changePassword(String username, String passChange1, String passChange2, String passChange3)
								throws WrongPasswordException, UnknownUserException, InvalidUserNameException;
}