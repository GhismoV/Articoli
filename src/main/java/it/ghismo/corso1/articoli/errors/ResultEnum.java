package it.ghismo.corso1.articoli.errors;

import java.util.Objects;

import it.ghismo.corso1.articoli.dto.ResultDto;

public enum ResultEnum {
	@Result(code = "0", msg = "Operazione eseguita")	
	Ok

	,@Result(code = "0", msg = "Operazione eseguita correttamente sull'elemento [%1$s]")	
	OkParam1
	
	,@Result(code = "0", msg = "Autenticazione OK")	
	AuthOk

	,@Result(code = "1", msg = "Elemento non trovato")
	NotFound
	
	,@Result(code = "2", msg = "%1$s con chiave di ricerca [%2$s] non trovato")
	NameKeySearchNotFound

	,@Result(code = "3", msg = "Errore di validazione sul campo [%1$s.%2$s] avente valore [%3$s]")
	BindingValidationError
	
	,@Result(code = "4", msg = "Articolo con codice [%1$s] già esistente. Utilizzare il servizio di modifica.")
	DuplicateError

	,@Result(code = "5", msg = "Il campo [%1$s] non può assumere il valore [%2$s]")
	InfoInvalidValueError

	,@Result(code = "6", msg = "Utente e/o Password non validi!!!")
	AuthenticationError
	;
	
	public Result getResult() {
		try {
			return ResultEnum.class.getDeclaredField(this.name()).getAnnotation(Result.class);
		} catch (NoSuchFieldException | SecurityException e) {
			return null;
		}
	}
	
	public ResultDto getDto() {
		Result r = getResult();
		return Objects.nonNull(r) ? new ResultDto(r.code(), r.msg()) : null; 
	}

	public ResultDto getDto(Object... params) {
		Result r = getResult();
		return Objects.nonNull(r) ? new ResultDto(r.code(), String.format(r.msg(), params) ) : null; 
	}
	
}
