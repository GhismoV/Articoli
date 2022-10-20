package it.ghismo.corso1.articoli.dto;

import lombok.Data;

@Data
public class IvaDto 
{
	private int idIva;
	private String descrizione;
	private int aliquota;
}
