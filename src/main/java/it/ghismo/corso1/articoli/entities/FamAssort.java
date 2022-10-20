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
@Table(name = "famassort")
@Data
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id")
public class FamAssort implements Serializable {
	private static final long serialVersionUID = -2515962168827215648L;
	
	@Id
	@Column(name = "id", nullable = false)
	private int id;
	
	@Column(name = "descrizione")
	private String descrizione;
	
//	@EqualsAndHashCode.Exclude
//	@ToString.Exclude
//	@OneToMany(fetch = FetchType.LAZY, mappedBy = "famAssort")
//	//@JsonBackReference
//	private Set<Articoli> articoli;
	
}
