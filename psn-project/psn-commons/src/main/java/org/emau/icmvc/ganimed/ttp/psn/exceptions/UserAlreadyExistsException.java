package org.emau.icmvc.ganimed.ttp.psn.exceptions;

import javax.xml.bind.annotation.XmlType;

@XmlType(name = "UserAlreadyExistsExceptionType", namespace = "http://psn.ttp.ganimed.icmvc.emau.org/")
public class UserAlreadyExistsException extends Exception {

	private static final long serialVersionUID = 4929466162656943875L;

	public UserAlreadyExistsException() {
		super();
	}

	public UserAlreadyExistsException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public UserAlreadyExistsException(final String message) {
		super(message);
	}

	public UserAlreadyExistsException(final Throwable cause) {
		super(cause);
	}
}
