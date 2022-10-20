package it.ghismo.corso1.articoli.entities;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;

import lombok.Data;

@Entity
@Table(name = "iva")
@Data
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "idIva")
public class Iva implements Serializable {
	private static final long serialVersionUID = -2515962168827215648L;
	
	@Id
	@Column(name = "idiva", nullable = false)
	private int idIva;
	
	@Column(name = "descrizione")
	private String descrizione;
	
	@Column(name = "aliquota")
	private Integer aliquota;
	
//	@EqualsAndHashCode.Exclude
//	@ToString.Exclude
//	@OneToMany(fetch = FetchType.LAZY, mappedBy = "iva")
//	//@JsonBackReference
//	private Set<Articoli> articoli;
	
}
