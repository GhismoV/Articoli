package it.ghismo.corso1.articoli.tests.RepositoryTests;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import it.ghismo.corso1.articoli.Application;
import it.ghismo.corso1.articoli.entities.Barcode;
import it.ghismo.corso1.articoli.repository.BarcodeRepository;

@SpringBootTest
@ContextConfiguration(classes = Application.class)
public class BarcodeRepositoryTest {
	@Autowired
	private BarcodeRepository barcodeRepository;
	
	
	@Test
	public void TestfindByBarcode() {
		String barcode = "8008490000021";
		assertThat(barcodeRepository.findByBarcode(barcode))
		.extracting(Barcode::getBarcode)
		.isEqualTo(barcode);
	}
	
}