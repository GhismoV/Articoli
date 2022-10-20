package it.ghismo.corso1.articoli.repository;

import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.ghismo.corso1.articoli.entities.Articoli;

public interface ArticoliRepository extends PagingAndSortingRepository<Articoli, String> {
	
	@Query(value = "select * from articoli where descrizione like :desArt", nativeQuery = true)
	List<Articoli> selByDescrizioneLike(@Param("desArt") String descr);
	
	List<Articoli> findByDescrizioneStartsWith(String descr);

	List<Articoli> findByDescrizioneLike(String descr, Pageable pageable);
	
	Articoli findByCodArt (String codArt);
	
	@Query("SELECT a FROM Articoli a JOIN a.barcode b WHERE b.barcode = :ean")
	Articoli selByEan(@Param("ean") String ean);
	
}
