package it.ghismo.corso1.articoli.services;

import java.util.List;

import it.ghismo.corso1.articoli.dto.ArticoliDto;
import it.ghismo.corso1.articoli.entities.Articoli;

public interface ArticoliService {
	ArticoliDto read(String key);
	ArticoliDto readByEan(String ean);
	List<ArticoliDto> readByDescr(String descr);
	List<ArticoliDto> readByDescr(String descr, int pageNum, int pageSize);
	Articoli insert(Articoli a);
	Articoli update(Articoli a);
	void delete(String key);
	
}
