package it.ghismo.corso1.articoli.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

@Service("customUserDetailsService")
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
	
	@Autowired
	@Qualifier("svc-gestuser-config")
	private ServiceConfig guc;
	
	@Autowired
	private RestTemplate restClient;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if(Objects.isNull(username) || username.length() < 4) {
			String err = "Username assente o non valido";
			log.error(err);
			throw new UsernameNotFoundException(err);
		}
		UtentiDto utenteTrovato = getUtenteFromService(username);
		if(Objects.isNull(utenteTrovato)) {
			String err = "Utente non trovato";
			log.error(err);
			throw new UsernameNotFoundException(err);
		}
		return buildUser(utenteTrovato.getUserId(), utenteTrovato.getPassword(), utenteTrovato.getAttivo(), utenteTrovato.getRuoli());
	}
	
	private UtentiDto getUtenteFromService(String uid) {
		String strUrl = guc.getUrl() + uid;
		try {
			URI url = new URI(strUrl);
			//restClient.getInterceptors().add(new BasicAuthenticationInterceptor(guc.getSecurityUid(), guc.getSecurityPwd()));
			return restClient.getForObject(url, UtentiDto.class);
		} catch (URISyntaxException e) {
			log.error("Connessione a GestUser non riuscita", e);
		}
		
		return null;
	}
	
	private UserDetails buildUser(String un, String p, String attivo, List<String> roles) {
		UserBuilder usersBuilder = User.builder();
		return usersBuilder
				.username(un)
				.password(p)
				.disabled(!"Si".equals(attivo))
				//.roles(roles.stream().toArray(String[]::new)) // ghismo : è la stessa cosa di authorities, ma mette automaticamente il prefisso "ROLE_"
				.authorities(roles.stream().map(r -> "ROLE_" + r).toArray(String[]::new))
				.build();
	}

}
