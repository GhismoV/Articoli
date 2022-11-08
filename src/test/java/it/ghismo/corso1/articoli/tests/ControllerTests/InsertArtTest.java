package it.ghismo.corso1.articoli.tests.ControllerTests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;

import org.json.JSONException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import it.ghismo.corso1.articoli.Application;
import it.ghismo.corso1.articoli.entities.Articoli;
import it.ghismo.corso1.articoli.repository.ArticoliRepository;

@ContextConfiguration(classes = Application.class)
@SpringBootTest
@TestMethodOrder(OrderAnnotation.class)
public class InsertArtTest
{
	 
    private MockMvc mockMvc;
	
	@Autowired
	private WebApplicationContext wac;
	
	@Autowired
	private ArticoliRepository repo;
	
	@BeforeEach
	public void setup() throws JSONException, IOException
	{
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.build();	
	}
	
	private String JsonData =  
					"{\n" + 
					"    \"codArt\": \"123Test\",\n" + 
					"    \"descrizione\": \"ARTICOLO TEST\",\n" + 
					"    \"um\": \"PZ\",\n" + 
					"    \"codStat\": \" TEST\",\n" + 
					"    \"pzCart\": 1,\n" + 
					"    \"pesoNetto\": 0,\n" + 
					"    \"idStatoArt\": \"1\",\n" + 
					"    \"dataCreaz\": \"2018-09-26\",\n" + 
					"	 \"famAssort\": {\n" + 
					"        \"id\": 1 \n" + 
					"    }\n" + 
					"}";
	
	String ErrJsonData =  
					"{\n" + 
					"    \"codArt\": \"123Test1\",\n" + 
					"    \"descrizione\": \"\",\n" + 
					"    \"um\": \"PZ\",\n" + 
					"    \"codStat\": \" TEST\",\n" + 
					"    \"pzCart\": 1,\n" + 
					"    \"pesoNetto\": 0,\n" + 
					"    \"idStatoArt\": \"1\",\n" + 
					"    \"dataCreaz\": \"2018-09-26\",\n" + 
					"	 \"famAssort\": {\n" + 
					"        \"id\": 1 \n" + 
					"    }\n" + 
					"}";
	
	private String JsonDataMod =  
			"{\n" + 
			"    \"codArt\": \"123Test\",\n" + 
			"    \"descrizione\": \"ARTICOLO TEST MODIF\",\n" + 
			"    \"um\": \"PZ\",\n" + 
			"    \"codStat\": \" TEST\",\n" + 
			"    \"pzCart\": 1,\n" + 
			"    \"pesoNetto\": 0,\n" + 
			"    \"idStatoArt\": \"1\",\n" + 
			"    \"dataCreaz\": \"2018-09-26\",\n" + 
			"	 \"famAssort\": {\n" + 
			"        \"id\": 1 \n" + 
			"    }\n" + 
			"}";
	
	@Test
	@Order(1)
	public void testInsArticolo() throws Exception
	{
		mockMvc.perform(MockMvcRequestBuilders.post("/api/articoli/inserisci")
				.contentType(MediaType.APPLICATION_JSON)
				.content(JsonData)
				.accept(MediaType.APPLICATION_JSON))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.code").value("0"))
				.andExpect(jsonPath("$.message").value("Operazione eseguita correttamente sull'elemento [123Test]"))
				.andDo(print());
		
		assertThat(repo.findByCodArt("123Test"))
		.extracting(Articoli::getDescrizione)
		.isEqualTo("ARTICOLO TEST");
		
	}
	
	@Test
	@Order(2)
	public void testErrInsArticolo1() throws Exception
	{
		mockMvc.perform(MockMvcRequestBuilders.post("/api/articoli/inserisci")
				.contentType(MediaType.APPLICATION_JSON)
				.content(JsonData)
				.accept(MediaType.APPLICATION_JSON))
				.andExpect(status().isNotAcceptable())
				.andExpect(jsonPath("$.code").value(4))
				.andExpect(jsonPath("$.message").value("Articolo con codice [123Test] già esistente. Utilizzare il servizio di modifica."))
				.andDo(print());
	}
		
	@Test
	@Order(3)
	public void testErrInsArticolo2() throws Exception
	{
		mockMvc.perform(MockMvcRequestBuilders.post("/api/articoli/inserisci")
				.contentType(MediaType.APPLICATION_JSON)
				.content(ErrJsonData)
				.accept(MediaType.APPLICATION_JSON))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$[0].code").value(3))
				.andExpect(jsonPath("$[0].message").value("Errore di validazione sul campo [articoli.descrizione] avente valore []"))
				.andDo(print());
	}
	
	@Test
	@Order(4)
	public void testUpdArticolo() throws Exception
	{
		mockMvc.perform(MockMvcRequestBuilders.put("/api/articoli/modifica")
				.contentType(MediaType.APPLICATION_JSON)
				.content(JsonDataMod)
				.accept(MediaType.APPLICATION_JSON))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.code").value("0"))
				.andExpect(jsonPath("$.message").value("Operazione eseguita correttamente sull'elemento [123Test]"))
				.andDo(print());

		assertThat(repo.findByCodArt("123Test"))
		.extracting(Articoli::getDescrizione)
		.isEqualTo("ARTICOLO TEST MODIF");
		
	}
	
	@Test
	@Order(5)
	public void testDelArticolo() throws Exception
	{
		mockMvc.perform(MockMvcRequestBuilders.delete("/api/articoli/elimina/123Test")
				.accept(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.code").value("0"))
				.andExpect(jsonPath("$.message").value("Operazione eseguita correttamente sull'elemento [123Test]"))
				.andDo(print());
	}
	
	
	
}
