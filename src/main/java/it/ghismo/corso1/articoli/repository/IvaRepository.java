package it.ghismo.corso1.articoli.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import it.ghismo.corso1.articoli.entities.Iva;

public interface IvaRepository extends JpaRepository<Iva, Integer> {
}
