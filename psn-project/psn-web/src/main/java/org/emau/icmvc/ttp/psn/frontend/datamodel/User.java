package org.emau.icmvc.ttp.psn.frontend.datamodel;

import java.io.Serializable;

public class User implements Serializable {

	private static final long serialVersionUID = -6621355803242144414L;

	private long id;
	private String username;
	private boolean admin;
	private boolean verified;
	
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
	
	
}
