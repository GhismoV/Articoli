package it.ghismo.corso1.articoli.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@RequiredArgsConstructor
public class ResultDto {
	@NonNull private String code;
	private String message;
	private LocalDateTime date = LocalDateTime.now();

	public ResultDto(@NonNull String codice, String messaggio) { this(codice, messaggio, LocalDateTime.now()); }
	
}
