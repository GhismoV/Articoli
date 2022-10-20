package it.ghismo.corso1.articoli.exceptions;

import org.springframework.http.HttpStatus;

import it.ghismo.corso1.articoli.dto.ResultDto;
import it.ghismo.corso1.articoli.errors.ResultEnum;
import lombok.Getter;


public abstract class BaseResultException extends Exception {
	private static final long serialVersionUID = -2404717895107950786L;
	
	private final static String DEFAULT_CODE = "1";
	
	@Getter
	protected ResultDto err;
	
	public BaseResultException(String message) { this(DEFAULT_CODE, message); }
	public BaseResultException(ResultEnum errEnum, Object... params) { 
		super(errEnum.getDto(params).getMessage());
		err = errEnum.getDto(params);
	}
	public BaseResultException(String code, String message) { this(new ResultDto(code, message)); }
	
	public BaseResultException(ResultDto err) { 
		super(err.getMessage());
		this.err = err;
	}
	
	public abstract HttpStatus getHttpStatus();
}
