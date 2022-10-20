package it.ghismo.corso1.articoli.services;

import it.ghismo.corso1.articoli.entities.Barcode;

public interface BarcodeService {
	Barcode read(String key);
}
