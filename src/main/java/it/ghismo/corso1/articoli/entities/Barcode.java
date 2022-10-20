package it.ghismo.corso1.articoli.entities;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

@Entity
@Table(name = "barcode")
@Data
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "barcode")
public class Barcode implements Serializable {
	private static final long serialVersionUID = -2515962168827215648L;
	
	@Id
	@Column(name = "barcode", nullable = false)
	@Pattern(regexp = "^\\d{6,13}$", message = "Pattern.Barcode.barcode.Validation")
	//@Size(min = 8, max = 13, message = "Size.Barcode.barcode.Validation")
	@NotNull(message = "NotNull.Barcode.barcode.Validation")
	private String barcode;

	@Column(name = "idtipoart")
	@NotNull(message = "NotNull.Barcode.idTipoArt.Validation")
	private String idTipoArt;

	@EqualsAndHashCode.Exclude
	@ToString.Exclude
	@ManyToOne
	@JoinColumn(name = "codart", referencedColumnName = "codArt")
	//@JsonBackReference
	private Articoli articolo;
	
	@ToString.Include(name = "id articolo")
	private String articoloToString() {
		return articolo != null ? articolo.getCodArt() : null;
	}
	
}
