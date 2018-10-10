package org.emau.icmvc.ganimed.ttp.psn.model;

import java.io.Serializable;
//import java.util.List;
import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Convert;
//import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.JoinColumn;
//import javax.persistence.Transient;

import org.emau.icmvc.ganimed.ttp.gstats.ejb.Statistic;
import org.emau.icmvc.ganimed.ttp.psn.internal.PasswordConverter;

//import org.emau.icmvc.ganimed.ttp.psn.internal.PasswordConverter;

@Entity
@Table(name = "users")
public class USR implements Serializable {

	private static final long serialVersionUID = 2894435231876207015L;

	@Id
	@Column(name = "id")
	private long id;
	
	@Column(name = "username")
	private String username;
	
	@Column(name = "password")
	//@Convert(converter = PasswordConverter.class)	
	private String password;
	
	@Column(name = "verified")
	private boolean verified;

	@Column(name = "admin")
	private boolean admin;
	
	@ManyToMany()
	  @JoinTable (name="BENUTZER_ROLLE", 
	    joinColumns={@JoinColumn(name="BENUTZER_ID") },
	    inverseJoinColumns={@JoinColumn(name="ROLLEN_ID") })
	private Collection<RolleBean> rollen;
	
	//@Transient
	//private List<USR> users;


	/**
	 * this constructor is only for reflection-based instantiation - do not use in other cases!
	 */
	public USR() {
	}

	public USR(Long id, String username, String password) {
		this.username = username;
		this.password = password;		
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

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	public boolean isVerified() {
		return verified;
	}

	public void setVerified(boolean verified) {
		this.verified = verified;
	}
	
	public boolean isAdmin() {
		return admin;
	}

	public void setAdmin(boolean admin) {
		this.admin = admin;
	}
//	public List<USR> getUserList() {
//		return users;
//	}

	public Collection<RolleBean> getRollen() {
		return rollen;
	}

	public void setRollen(Collection<RolleBean> rollen) {
		this.rollen = rollen;
	}
	
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (id ^ (id >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		USR other = (USR) obj;
		if (id != other.id)
			return false;
		return true;
	}	

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("username '");
		sb.append(username);
		return sb.toString();
	}
}
