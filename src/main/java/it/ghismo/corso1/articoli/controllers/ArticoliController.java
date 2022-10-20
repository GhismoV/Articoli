package it.ghismo.corso1.articoli.controllers;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import it.ghismo.corso1.articoli.dto.ArticoliDto;
import it.ghismo.corso1.articoli.dto.ResultDto;
import it.ghismo.corso1.articoli.entities.Articoli;
import it.ghismo.corso1.articoli.entities.Barcode;
import it.ghismo.corso1.articoli.errors.ResultEnum;
import it.ghismo.corso1.articoli.exceptions.BindingValidationException;
import it.ghismo.corso1.articoli.exceptions.DuplicateException;
import it.ghismo.corso1.articoli.exceptions.NotFoundException;
import it.ghismo.corso1.articoli.services.ArticoliService;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/articoli")
@CrossOrigin(value = {"http://localhost:4200"})
@Slf4j
@Validated
public class ArticoliController {
	@Autowired private ArticoliService articoliSvc;
	
	//@Autowired private BarcodeService barcodeSvc;
	
	@Autowired
	private ResourceBundleMessageSource rb;
	
	
	@GetMapping(value = "/testAuth", produces = {MediaType.APPLICATION_JSON_VALUE})
	@SneakyThrows
	public ResponseEntity<ResultDto> testAuth() {
		return new ResponseEntity<ResultDto>(ResultEnum.AuthOk.getDto(), HttpStatus.OK);
	}
	

	@GetMapping(value = "/cerca/barcode/{barcode}", produces = MediaType.APPLICATION_JSON_VALUE)
	@Validated
	@SneakyThrows
	public ResponseEntity<ArticoliDto> cercaByBarcode(
			@PathVariable(name = "barcode", required = true)
			@NotNull
			@Pattern(regexp = "[0-9]{8,13}")
			String eanBarcode) {
		
		log.debug("**** Cerchiamo di ottenere l'articolo attraverso il codice EAN [{}] del barcode ****", eanBarcode);
		/*
		Barcode barcode = barcodeSvc.read(eanBarcode);
		Articoli articolo = null;
		if(barcode != null) {
			articolo = barcode.getArticolo();
		}
		log.info("Barcode: {}", barcode);
		*/
		ArticoliDto articolo = articoliSvc.readByEan(eanBarcode);
				
		log.info("Articolo: {}", articolo);
		
		if(articolo == null) throw new NotFoundException("Barcode", eanBarcode);
		
		return new ResponseEntity<ArticoliDto>(articolo, HttpStatus.OK);
	}

	@GetMapping(value = "/cerca/codice/{codArt}", produces = MediaType.APPLICATION_JSON_VALUE)
	@SneakyThrows
	public ResponseEntity<ArticoliDto> cercaByArtCode(
			@PathVariable(name = "codArt", required = true)
			@NotNull
			@Pattern(regexp = "[0-9]{8,13}")
			String codArt) {
		
		log.debug("**** Cerchiamo di ottenere l'articolo attraverso il codice Articolo [{}] ****", codArt);
		
		ArticoliDto articolo = articoliSvc.read(codArt);
		log.info("Articolo: {}", articolo);
		
		if(articolo == null) throw new NotFoundException("L'Articolo", codArt);
		
		return new ResponseEntity<ArticoliDto>(articolo, HttpStatus.OK);
	}
	
	@GetMapping(value = "/cerca/descrizione/{descr}", produces = MediaType.APPLICATION_JSON_VALUE)
	@Validated
	@SneakyThrows
	public ResponseEntity<List<ArticoliDto>> cercaByDescr(
			@PathVariable(name = "descr", required = true)
			@NotNull
			String descr) {
		
		log.debug("**** Cerchiamo di ottenere l'articolo attraverso la descrizione[{}] ****", descr);
		
		List<ArticoliDto> articoli = articoliSvc.readByDescr(descr.toUpperCase());
		log.info("Articoli: {}", articoli);
		if(Objects.isNull(articoli) || articoli.isEmpty()) throw new NotFoundException("Articoli", descr);
		
		return new ResponseEntity<List<ArticoliDto>>(articoli, HttpStatus.OK);
	}
	
	@PostMapping(value = "/inserisci", consumes = {MediaType.APPLICATION_JSON_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE})
	@SneakyThrows
	public ResponseEntity<ResultDto> createArt(
			@RequestBody(required = true)
			@Valid
			Articoli articoloIn,
			
			BindingResult bindingResult
			) {
		log.debug("**** Cerchiamo di inserire l'articolo [{}]", articoloIn.getCodArt());

		ArticoliDto articoloChk = checkInputArt(articoloIn, bindingResult);
		if(articoloChk != null) {
			log.warn("Articolo [{}] già esistente... Usare PUT", articoloIn.getCodArt());
			throw new DuplicateException(articoloIn.getCodArt());
		}

		Set<Barcode> barcodes = articoloIn.getBarcode();
		if(barcodes != null) {
			articoloIn.setBarcode(barcodes.stream().filter(b -> !Strings.isBlank(b.getBarcode())).collect(Collectors.toSet()));
			articoloIn.getBarcode().stream().forEach(b -> b.setArticolo(articoloIn));
		}
		
		Articoli outEntity = articoliSvc.insert(articoloIn);
		
		return new ResponseEntity<ResultDto>(ResultEnum.OkParam1.getDto(outEntity.getCodArt()), HttpStatus.CREATED);
	}
	
	@RequestMapping(value = "/modifica", method = RequestMethod.PUT, consumes = {MediaType.APPLICATION_JSON_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE})
	@SneakyThrows
	public ResponseEntity<ResultDto> updateArt(
			@RequestBody(required = true)
			@Valid
			Articoli articoloIn,
			
			BindingResult bindingResult
			) {
		log.debug("**** Cerchiamo di modificare l'articolo [{}]", articoloIn.getCodArt());

		ArticoliDto articoloChk = checkInputArt(articoloIn, bindingResult);
		if(articoloChk == null) {
			log.warn("Articolo [{}] non trovato.", articoloIn.getCodArt());
			throw new NotFoundException("Articolo", articoloIn.getCodArt());
		}

		articoloIn.getBarcode().stream().forEach(b -> b.setArticolo(articoloIn));
		if(articoloIn.getIngredienti() != null) {
			articoloIn.getIngredienti().setCodart(articoloIn.getCodArt());
			//articoloIn.getIngredienti().setArticolo(articoloIn);
		}

		Articoli outEntity = articoliSvc.update(articoloIn);
		
		return new ResponseEntity<ResultDto>(ResultEnum.OkParam1.getDto(outEntity.getCodArt()), HttpStatus.CREATED);
	}
	
	
	@RequestMapping(value = "/elimina/{codArt}", method = RequestMethod.DELETE, produces = {MediaType.APPLICATION_JSON_VALUE})
	@SneakyThrows
	public ResponseEntity<ResultDto> deleteArt(
			@PathVariable(name = "codArt", required = true)
			@NotNull
			@Pattern(regexp = "[0-9]{8,13}")
			String codArt) {
		log.debug("**** Cerchiamo di eliminare l'articolo [{}]", codArt);

		ArticoliDto articoloChk = articoliSvc.read(codArt);
		if(articoloChk == null) {
			log.warn("Articolo [{}] non trovato.", codArt);
			throw new NotFoundException("Articolo", codArt);
		} else if(!(codArt.equalsIgnoreCase("123Test") || articoloChk.getDescrizione().toUpperCase().contains("GHISMO")) ) {
			log.warn("Articolo [{}] fa parte della base dati del corso e quindi non è eliminabile", codArt);
			throw new DuplicateException(codArt);
		}

		articoliSvc.delete(codArt);
		
		return new ResponseEntity<ResultDto>(ResultEnum.OkParam1.getDto(codArt), HttpStatus.OK);
	}
	
	
	@SneakyThrows
	private ArticoliDto checkInputArt(Articoli articoloIn, BindingResult bindingResult) {
		log.debug("Articolo: {}", articoloIn.toString());
		if(bindingResult.hasErrors()) {
			FieldError f = bindingResult.getFieldError();
			String errTranslated = rb.getMessage(f, LocaleContextHolder.getLocale());
			log.warn(errTranslated);
			throw new BindingValidationException(f);
		}
		if(articoloIn.getIva() != null && articoloIn.getIva().getIdIva() == -1) {
			throw new BindingValidationException("Iva", -1);
		}
		return articoliSvc.read(articoloIn.getCodArt());
	}
	
	
}
