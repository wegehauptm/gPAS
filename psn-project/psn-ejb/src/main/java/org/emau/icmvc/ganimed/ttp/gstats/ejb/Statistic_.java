package org.emau.icmvc.ganimed.ttp.gstats.ejb;

import javax.annotation.Generated;
import javax.persistence.metamodel.MapAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value="Dali", date="2018-08-21T14:50:03.623+0200")
@StaticMetamodel(Statistic.class)
public class Statistic_ {
	public static volatile SingularAttribute<Statistic, Long> stat_entry_id;
	public static volatile SingularAttribute<Statistic, String> entrydate;
	public static volatile MapAttribute<Statistic, String, String> mappedStatValue;
}
