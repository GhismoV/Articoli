package it.ghismo.corso1.articoli.dto;

import io.micrometer.core.lang.NonNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@RequiredArgsConstructor
public class DataResultDto<D> {
	@NonNull private ResultDto result;
	private D data;
}
