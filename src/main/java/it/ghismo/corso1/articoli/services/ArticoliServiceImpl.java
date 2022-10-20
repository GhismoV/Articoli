package it.ghismo.corso1.articoli.services;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.ghismo.corso1.articoli.dto.ArticoliDto;
import it.ghismo.corso1.articoli.entities.Articoli;
import it.ghismo.corso1.articoli.repository.ArticoliRepository;

@Service
@Transactional(readOnly = true)
public class ArticoliServiceImpl implements ArticoliService {
	@Autowired
	private ArticoliRepository rep;
	
	@Autowired
	private ModelMapper mm;
	
	@Override
	public ArticoliDto read(String key) {
		Optional<Articoli> opt = rep.findById(key);
		return opt.isPresent() ? mm.map(opt.get(), ArticoliDto.class) : null;
	}

	@Override
	public ArticoliDto readByEan(String ean) {
		Articoli a = rep.selByEan(ean);
		return a != null ? mm.map(a, ArticoliDto.class) : null;
	}
	

	@Override
	public List<ArticoliDto> readByDescr(String descr) {
		List<Articoli> eList = rep.selByDescrizioneLike("%" + descr + "%");
		return eList.stream().map(e -> mm.map(e, ArticoliDto.class)).collect(Collectors.toList());
	}

	@Override
	public List<ArticoliDto> readByDescr(String descr, int pageNum, int pageSize) {
		List<Articoli> eList = rep.findByDescrizioneLike(descr, PageRequest.of(pageNum - 1, pageSize));
		return eList.stream().map(e -> mm.map(e, ArticoliDto.class)).collect(Collectors.toList());
	}

	@Override
	@Transactional
	public Articoli insert(Articoli a) {
		a.setDescrizione(a.getDescrizione().toUpperCase());
		return rep.save(a);
	}

	@Override
	@Transactional
	public Articoli update(Articoli a) {
		a.setDescrizione(a.getDescrizione().toUpperCase());
		return rep.save(a);
	}

	@Override
	@Transactional
	public void delete(String key) {
		rep.deleteById(key);
	}

}
