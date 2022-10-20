package it.ghismo.corso1.articoli.exceptions;

import org.springframework.http.HttpStatus;

import it.ghismo.corso1.articoli.errors.ResultEnum;

public class DuplicateException extends BaseResultException {
	private static final long serialVersionUID = -2404717895107950786L;
	
	public DuplicateException(String cod) {
		super(ResultEnum.DuplicateError, cod); 
	}


	@Override public HttpStatus getHttpStatus() { return HttpStatus.NOT_ACCEPTABLE; }

}
