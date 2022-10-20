package it.ghismo.corso1.articoli.services;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.ghismo.corso1.articoli.dto.CategoriaDto;
import it.ghismo.corso1.articoli.repository.FamAssortRepository;

@Service
@Transactional(readOnly = true)
public class FamAssortServiceImpl implements FamAssortService {

	@Autowired
	private FamAssortRepository rep;
	
	@Autowired
	ModelMapper mm;
	
	@Override
	public List<CategoriaDto> readAll() {
		return rep.findAll().stream().map(i -> mm.map(i, CategoriaDto.class)).collect(Collectors.toList());
	}

}
