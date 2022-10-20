package it.ghismo.corso1.articoli.services;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.ghismo.corso1.articoli.dto.IvaDto;
import it.ghismo.corso1.articoli.repository.IvaRepository;

@Service
@Transactional(readOnly = true)
public class IvaServiceImpl implements IvaService {

	@Autowired
	private IvaRepository rep;
	
	@Autowired
	ModelMapper mm;
	
	@Override
	public List<IvaDto> readAll() {
		return rep.findAll().stream().map(i -> mm.map(i, IvaDto.class)).collect(Collectors.toList());
	}

}
