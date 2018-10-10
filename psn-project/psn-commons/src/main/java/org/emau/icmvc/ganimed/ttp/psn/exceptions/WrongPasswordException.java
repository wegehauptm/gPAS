package org.emau.icmvc.ganimed.ttp.psn.exceptions;

import javax.xml.bind.annotation.XmlType;

@XmlType(name = "WrongPasswordExceptionType", namespace = "http://psn.ttp.ganimed.icmvc.emau.org/")
public class WrongPasswordException extends Exception {

	private static final long serialVersionUID = 4929466162656943871L;

	public WrongPasswordException() {
		super();
	}

	public WrongPasswordException(final String message, final Throwable cause) {
		super(message, cause);
	}

	public WrongPasswordException(final String message) {
		super(message);
	}

	public WrongPasswordException(final Throwable cause) {
		super(cause);
	}
}
