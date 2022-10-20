package it.ghismo.corso1.articoli.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.ghismo.corso1.articoli.entities.Barcode;
import it.ghismo.corso1.articoli.repository.BarcodeRepository;

@Service
@Transactional(readOnly = true)
public class BarcodeServiceImpl implements BarcodeService {

	@Autowired
	private BarcodeRepository rep;
	
	@Override
	public Barcode read(String key) {
		return rep.findByBarcode(key);
	}

}
