package it.ghismo.corso1.articoli.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import it.ghismo.corso1.articoli.dto.CategoriaDto;
import it.ghismo.corso1.articoli.services.FamAssortService;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/categoria")
@CrossOrigin(value = "http://localhost:4200")
@Slf4j
public class CategoriaController {
	@Autowired private FamAssortService svc;
	

	@GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
	@Validated
	@SneakyThrows
	public ResponseEntity<List<CategoriaDto>> getAll() {
		log.debug("**** Cerchiamo la lista di tutte le categorie ****");
		List<CategoriaDto> out = svc.readAll();
		log.debug("Lista Categorie: {}", out);
		return new ResponseEntity<List<CategoriaDto>>(out, HttpStatus.OK);
	}
	
}
