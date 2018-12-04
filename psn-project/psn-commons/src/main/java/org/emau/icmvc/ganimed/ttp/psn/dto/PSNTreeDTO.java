package org.emau.icmvc.ganimed.ttp.psn.dto;

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
import java.util.List;


/**
 * dto for PsnTreeNode
 * 
 * @author wolffr
 * TODO  hashCode und equals Wegehaupt
 */
public class PSNTreeDTO extends PSNDTO {

	private static final long serialVersionUID = 82972503364950287L;
	private List<PSNTreeDTO> children = new ArrayList<PSNTreeDTO>();

	public PSNTreeDTO() {
	}

	public PSNTreeDTO(String domain, String pseudonym, Long createdDate, Long expiryDate) {
		super(domain, null,pseudonym, createdDate, expiryDate);
	}
	
	public List<PSNTreeDTO> getChildren() {
		return children;
	}

	public void setChildren(List<PSNTreeDTO> children) {
		this.children = children;
	}
	
	public void addChild(PSNTreeDTO child) {
		children.add(child);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((children == null) ? 0 : children.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		PSNTreeDTO other = (PSNTreeDTO) obj;
		if (children == null) {
			if (other.children != null)
				return false;
		} else if (!children.equals(other.children))
			return false;
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append(" with ");
		sb.append(children.size());
		sb.append(" children");
		return sb.toString();
	}
}
