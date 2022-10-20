package it.ghismo.corso1.articoli;

import org.modelmapper.AbstractConverter;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.ghismo.corso1.articoli.dto.ArticoliDto;
import it.ghismo.corso1.articoli.entities.Articoli;

@Configuration
public class ModelMapperConfig {
	// org.springframework.beans.BeanUtils
	
	@Bean
	public ModelMapper modelMapper() {
		Converter<String, String> converter = new AbstractConverter<>() {
			@Override protected String convert(String source) {
				return source != null ? source.trim() : null;
			}
		};
		

		ModelMapper mm = new ModelMapper();
		mm.getConfiguration().setSkipNullEnabled(true);

		mm.addConverter(converter);
		
		/*
		mm.addMappings(new PropertyMap<Articoli, ArticoliDto>() {
			@Override protected void configure() { this.map().setDataCreazione(this.source.getDataCreaz()); }
		});
		*/
		
		/*
		mm.addMappings(new PropertyMap<Barcode, BarcodeDto>() {
			@Override protected void configure() { this.map().setTipo(this.source.getIdTipoArt()); }
		});
		*/
		
		return mm;
	}
	
	
}
