package it.ghismo.corso1.articoli.exceptions;

import org.springframework.http.HttpStatus;

import it.ghismo.corso1.articoli.errors.ResultEnum;


public class NotFoundException extends BaseResultException {
	private static final long serialVersionUID = -2404717895107950786L;
	
	public NotFoundException() { 
		super(ResultEnum.NotFound); 
	}
	
	public NotFoundException(String infoName, String infoId) {
		super(ResultEnum.NameKeySearchNotFound, infoName, infoId); 
	}


	@Override public HttpStatus getHttpStatus() { return HttpStatus.NOT_FOUND; }

}
