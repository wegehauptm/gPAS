package org.emau.icmvc.ganimed.ttp.psn.exceptions;


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


	import javax.xml.bind.annotation.XmlType;

	/**
	 * should be thrown when the given domain isn't found within the db
	 * 
	 * @author geidell
	 *
	 */
	@XmlType(name = "UnknownUserExceptionType", namespace = "http://psn.ttp.ganimed.icmvc.emau.org/")
	public class UnknownUserException extends Exception {

		private static final long serialVersionUID = 4904637748275393911L;

		public UnknownUserException() {
			super();
		}

		public UnknownUserException(final String message, final Throwable cause) {
			super(message, cause);
		}

		public UnknownUserException(final String message) {
			super(message);
		}

		public UnknownUserException(final Throwable cause) {
			super(cause);
		}
	}
