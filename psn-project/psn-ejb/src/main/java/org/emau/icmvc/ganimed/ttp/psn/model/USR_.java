package org.emau.icmvc.ganimed.ttp.psn.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.CollectionAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value="Dali", date="2018-10-02T09:56:48.491+0200")
@StaticMetamodel(USR.class)
public class USR_ {
	public static volatile SingularAttribute<USR, Long> id;
	public static volatile SingularAttribute<USR, String> username;
	public static volatile SingularAttribute<USR, String> password;
	public static volatile SingularAttribute<USR, Boolean> verified;
	public static volatile SingularAttribute<USR, Boolean> admin;
	public static volatile CollectionAttribute<USR, RolleBean> rollen;
}
