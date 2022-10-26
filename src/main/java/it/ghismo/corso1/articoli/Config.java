package it.ghismo.corso1.articoli;


import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.web.client.RestTemplate;

import it.ghismo.corso1.articoli.security.ServiceConfig;



@Configuration
public class Config {
	

	@Bean
	public RestTemplate getRestTemplate(RestTemplateBuilder rtb, @Qualifier("svc-gestuser-config") ServiceConfig guc) {
		return rtb.additionalInterceptors(new BasicAuthenticationInterceptor(guc.getSecurityUid(), guc.getSecurityPwd())).build();
	}
	
	@Bean("svc-gestuser-config")
	@ConfigurationProperties(prefix = "services.gestuser")
	public ServiceConfig getGestuserConfig() {
		return new ServiceConfig();
	}
	
	
}
