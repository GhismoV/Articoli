package it.ghismo.corso1.articoli.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration /*extends WebSecurityConfigurerAdapter*/ {

	public static final String REALM = "REAME";
	
	private static final String[] USER_SVC 	= {
												"/api/articoli/cerca/**",
												"/api/articoli/testAuth"
												};
	private static final String[] ADMIN_SVC = {
												"/api/articoli/inserisci/**", 
												"/api/articoli/modifica/**",
												"/api/articoli/elimina/**"
												};
	
	@Autowired
	@Qualifier("customUserDetailsService")
	private CustomUserDetailsService userDetailsService;
	
	
	@Bean
	public BCryptPasswordEncoder getPwdEncoder() { return new BCryptPasswordEncoder(); }
	
	/*
	@Bean
	public UserDetailsService userDetailsService(BCryptPasswordEncoder bCryptPasswordEncoder) {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(buildUser(bCryptPasswordEncoder, "Ghismo", "banana", "USER"));
		manager.createUser(buildUser(bCryptPasswordEncoder, "Admin", "megabanana", "ADMIN", "USER"));
		return manager;
	}
	private UserDetails buildUser(BCryptPasswordEncoder bCryptPasswordEncoder, String un, String p, String... roles) {
		UserBuilder usersBuilder = User.builder();
		return usersBuilder
				.username(un)
				.password(bCryptPasswordEncoder.encode(p))
				.roles(roles)
				.build();
	}
	*/
	
	/*
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
		.userDetailsService(this.userDetailsService)
		.passwordEncoder(getPwdEncoder());
	}
	*/
	
	
	@Bean
	public AuthenticationManager authManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder/*, UserDetailsService userDetailService*/) 
	  throws Exception {
	    return http.getSharedObject(AuthenticationManagerBuilder.class)
	      .userDetailsService(this.userDetailsService)
	      .passwordEncoder(bCryptPasswordEncoder)
	      .and()
	      .build();
	}	

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    http
	    .cors() // serve per abilitare un filtro CORS per evitare l'errore CORS sulle preflight request (OPTION)
	    .and()
	    .csrf().disable()
	    .authorizeRequests()
			.antMatchers(USER_SVC).hasRole("USER")
			.antMatchers(ADMIN_SVC).hasRole("ADMIN")
			.antMatchers("/login/**").anonymous()
	    .anyRequest().authenticated()
	    .and()
			.httpBasic().realmName(REALM).authenticationEntryPoint(new AuthEntryPoint())
		.and()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

	    return http.build();
	}

	
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
	    return (web) -> 
	    	web
	    	.ignoring()
	    	.antMatchers("/css/**", "/js/**", "/img/**", "/lib/**", "/favicon.ico")
	    	.antMatchers(HttpMethod.OPTIONS, "/**");
	}
	
}
