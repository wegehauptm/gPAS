package org.emau.icmvc.ganimed.ttp.psn.model;

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

import java.io.Serializable;

import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;

import org.eclipse.persistence.annotations.Cache;
import org.eclipse.persistence.annotations.CacheCoordinationType;
import org.eclipse.persistence.annotations.CacheType;
import org.emau.icmvc.ganimed.ttp.psn.dto.PSNDTO;

/**
 * the persistence class for a pseudonym
 * 
 * @author geidell
 * 
 */
@Entity
@Cache(
		  type=CacheType.FULL,
		  size=128000,  // Use 128,000 as the initial cache size.
		  expiry=360000,  // 6 minutes
		  coordinationType=CacheCoordinationType.INVALIDATE_CHANGED_OBJECTS  // if cache coordination is used, only send invalidation messages.
		)
@Table(name = "psn", uniqueConstraints = @UniqueConstraint(columnNames = { "domain", "pseudonym" }, name = "domain_pseudonym"))//columnNames = { "domain", "originalValue", "pseudonym" } formerly. wrong i guess.
public class PSN implements Serializable {

	private static final long serialVersionUID = -4303062729589967516L;
	@EmbeddedId
	private PSNKey key;
	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "domain", referencedColumnName = "domain")
	@MapsId("domain")
	private PSNProject psnProject;
	//private String pseudonym;
	private Long createdDate;
	private Long expiryDate;

	/**
	 * this constructor is only for reflection-based instantiation - do not use in other cases!
	 */
	public PSN() {
	}

	public PSN(PSNProject parent, String originalValue, String pseudonym, Long createdDate, Long expiryDate) {
		super();
		this.key = new PSNKey(originalValue, parent.getDomain(), pseudonym);
		//this.pseudonym = pseudonym;
		this.psnProject = parent;
		this.createdDate = createdDate;
		this.expiryDate = expiryDate;
	}

	public PSNKey getKey() {
		return key;
	}

//	public String getPseudonym() {
//		return this.key.getPseudonym();
//	}

	public PSNProject getPSNProject() {
		return psnProject;
	}

	public PSNDTO toPSNDTO() {
		return new PSNDTO(key.getDomain(), key.getOriginValue(), key.getPseudonym(), createdDate, expiryDate);
	}		

	public Long getCreatedDate() {
		return createdDate;
	}

	public Long getExpiryDate() {
		return expiryDate;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (key == null ? 0 : key.hashCode());
		result = prime * result + (createdDate == null ? 0 : createdDate.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		PSN other = (PSN) obj;
		if (key == null) {
			if (other.key != null) {
				return false;
			}
		} else if (!key.equals(other.key)) {
			return false;
		} else if(!createdDate.equals(other.createdDate)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		String result;
		if (key == null) {
			result = "domain and original value are null for this PSN object";
		} else {
			StringBuilder sb = new StringBuilder();
			sb.append("PSN for domain '");
			sb.append(key.getDomain());
			sb.append("' and original value '");
			sb.append(key.getOriginValue());
			sb.append("'");
			result = sb.toString();
		}
		return result;
	}
}
