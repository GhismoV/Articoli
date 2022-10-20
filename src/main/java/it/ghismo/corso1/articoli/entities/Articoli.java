package it.ghismo.corso1.articoli.entities;

import java.io.Serializable;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Entity
@Table(name = "articoli")
@Data
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "codArt")
public class Articoli implements Serializable {
	private static final long serialVersionUID = -2515962168827215648L;
	
	@Id
	@Column(name = "codart", nullable = false)
	@Size(min = 5, max = 20, message = "Size.Articoli.codArt.Validation")
	@NotNull(message = "NotNull.Articoli.codArt.Validation")
	private String codArt;
	
	@Column(name = "descrizione")
	@Size(min = 6, max = 80, message = "Size.Articoli.descrizione.Validation")
	@NotNull(message = "NotNull.Articoli.descrizione.Validation")
	private String descrizione;
	
	@Column(name = "um")
	private String um;
	
	@Column(name = "codstat")
	private String codStat;
	
	@Column(name = "pzcart")
	@Max(value = 99, message = "Max.Articoli.pzCart.Validation")
	private Integer pzCart;
	
	@Column(name = "pesonetto")
	@Min(value = (long)0.01, message = "Min.Articoli.pesoNetto.Validation")
	private Double pesoNetto;
	
	@Column(name = "idstatoart")
	@NotNull(message = "NotNull.Articoli.idStatoArt.Validation")
	private String idStatoArt;
	
	@Temporal(TemporalType.DATE)
	@Column(name = "datacreazione")
	private Date dataCreazione;
	
	@EqualsAndHashCode.Exclude
	@OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL, mappedBy = "articolo", orphanRemoval = true)
	//@JsonManagedReference
	private Set<Barcode> barcode = new HashSet<>();
	
	@OneToOne(cascade = CascadeType.ALL, mappedBy = "articolo", orphanRemoval = true)
	private Ingredienti ingredienti;
	
	@EqualsAndHashCode.Exclude
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "idiva", referencedColumnName = "idIva")
	//@JsonManagedReference
	private Iva iva;

	@EqualsAndHashCode.Exclude
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "idfamass", referencedColumnName = "id")
	//@JsonManagedReference
	private FamAssort famAssort;
	
}
