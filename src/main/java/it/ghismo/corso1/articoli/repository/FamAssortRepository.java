package it.ghismo.corso1.articoli.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import it.ghismo.corso1.articoli.entities.FamAssort;

public interface FamAssortRepository extends JpaRepository<FamAssort, Integer> {
}
