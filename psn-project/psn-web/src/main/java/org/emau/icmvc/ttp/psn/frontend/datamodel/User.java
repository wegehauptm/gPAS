package org.emau.icmvc.ttp.psn.frontend.datamodel;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class User implements Serializable {

	private static final long serialVersionUID = -6621355803242144414L;

	private long id;
	private String username;
	private boolean admin;
	private boolean verified;
	private List<String> roles;
	
	public User() {
		super();
	}
	
	public User(long id, String username, boolean admin, boolean verified) {
		super();
		this.id = id;
		this.username = username;
		this.admin = admin;
		this.verified = verified;
	}
	
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public boolean isAdmin() {
		return admin;
	}
	public void setAdmin(boolean admin) {
		this.admin = admin;
	}
	public boolean isVerified() {
		return verified;
	}
	public void setVerified(boolean verified) {
		this.verified = verified;
	}
	public List<String> getRoles() {
		return roles;
	}
	public void addRole(String role) {
		if(roles==null)
			roles=new ArrayList<String>();
		this.roles.add(role);
	}	
	public void deleteRole(String role) {
		if(roles!=null)
			this.roles.remove(role);
	}
	
}
