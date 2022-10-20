package it.ghismo.corso1.articoli.entities;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;

@Entity
@Table(name = "ingredienti")
@Data
public class Ingredienti implements Serializable {
	private static final long serialVersionUID = -2515962168827215648L;
	
	@Id
	@Column(name = "codart", nullable = false)
	private String codart;

	@Column(name = "info")
	private String info;
	
	@OneToOne
	@PrimaryKeyJoinColumn
	@JsonIgnore
	private Articoli articolo;

	
}
