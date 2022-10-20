package it.ghismo.corso1.articoli.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.validation.FieldError;

import it.ghismo.corso1.articoli.errors.ResultEnum;

public class BindingValidationException extends BaseResultException {
	private static final long serialVersionUID = -2404717895107950786L;
	
	public BindingValidationException(FieldError field) {
		super(ResultEnum.BindingValidationError, field.getObjectName(), field.getField(), field.getRejectedValue()); 
		/*
		log.error("----------- ghismo - code" + field.getCode());
		log.error("----------- ghismo - DefaultMessage" + field.getDefaultMessage());
		log.error("----------- ghismo - Field" + field.getField());
		log.error("----------- ghismo - ObjectName" + field.getObjectName());
		log.error("----------- ghismo - Args" + field.getArguments());
		log.error("----------- ghismo - class" + field.getClass());
		log.error("----------- ghismo - codes" + field.getCodes());
		log.error("----------- ghismo - rejected" + field.getRejectedValue());
		*/
	}

	public BindingValidationException(String infoName, Object infoValue) {
		super(ResultEnum.InfoInvalidValueError, infoName, infoValue); 
	}

	@Override public HttpStatus getHttpStatus() { return HttpStatus.BAD_REQUEST; }

}
