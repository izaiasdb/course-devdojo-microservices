package br.com.idb.idbauth.config;

/*
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;

import br.gov.ce.sap.sapauth.security.filter.JwtUsernameAndPasswordAuthenticationFilter;
import br.gov.ce.sap.sapcore.property.JwtConfiguration;
import lombok.RequiredArgsConstructor;

@EnableWebSecurity
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class SecurityCredentialsConfigAula04 extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;
	private final JwtConfiguration jwtConfiguration;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
    	http
			.csrf().disable()
			.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
			.and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.exceptionHandling().authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED))	
			.and()
				.addFilter(new JwtUsernameAndPasswordAuthenticationFilter())
			.authorizeRequests()
				.antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
				.antMatchers("pessoa/admin/**").hasRole("ADMIN")
				.anyRequest().authenticated();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}	
} */