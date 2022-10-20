package it.ghismo.corso1.articoli.tests.RepositoryTests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ContextConfiguration;

import it.ghismo.corso1.articoli.Application;
import it.ghismo.corso1.articoli.entities.Articoli;
import it.ghismo.corso1.articoli.repository.ArticoliRepository;

@SpringBootTest()
@ContextConfiguration(classes = Application.class)
public class ArticoliRepositoryTest {
	
	@Autowired
	private ArticoliRepository articoliRepository;

	@Test
	public void TestfindByDescrizioneLike()	{
		List<Articoli> items = articoliRepository.selByDescrizioneLike("ACQUA ULIVETO%");
		assertEquals(2, items.size());
	}
	
	@Test
	public void TestfindByDescrizioneLikePage()	{
		List<Articoli> items = articoliRepository.findByDescrizioneLike("ACQUA%", PageRequest.of(0, 10));
		assertEquals(10, items.size());
	}

	@Test
	public void TestfindByCodArt() throws Exception	{	
		assertThat(articoliRepository.findByCodArt("002000301"))
				.extracting(Articoli::getDescrizione)
				.isEqualTo("ACQUA ULIVETO 15 LT");
	}

	@Test
	public void TestSelByEan() throws Exception	{	
		assertThat(articoliRepository.selByEan("8008490000021"))
				.extracting(Articoli::getDescrizione)
				.isEqualTo("ACQUA ULIVETO 15 LT");
	}
	
}
