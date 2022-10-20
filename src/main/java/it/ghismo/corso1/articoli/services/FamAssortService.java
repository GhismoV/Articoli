package it.ghismo.corso1.articoli.services;

import java.util.List;

import it.ghismo.corso1.articoli.dto.CategoriaDto;

public interface FamAssortService {
	List<CategoriaDto> readAll();
}
