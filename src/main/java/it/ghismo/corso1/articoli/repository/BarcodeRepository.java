package it.ghismo.corso1.articoli.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import it.ghismo.corso1.articoli.entities.Barcode;

public interface BarcodeRepository extends JpaRepository<Barcode, String> {
	public Barcode findByBarcode(String barcode);
}
