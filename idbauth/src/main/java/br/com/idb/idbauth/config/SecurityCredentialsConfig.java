package br.com.idb.idbauth.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.com.idb.idbauth.filter.JwtUsernameAndPasswordAuthenticationFilter;
import br.com.idb.idbcore.property.JwtConfiguration;
import br.com.idb.idbtoken.security.config.SecurityTokenConfig;
import br.com.idb.idbtoken.security.filter.JwtTokenAuthorizationFilter;
import br.com.idb.idbtoken.security.token.converter.TokenConverter;
import br.com.idb.idbtoken.security.token.creator.TokenCreator;

/**
 * @author William Suane
 */
//Aula 05	
//@EnableWebSecurity
//@RequiredArgsConstructor(onConstructor = @__(@Autowired))
//public class SecurityCredentialsConfig extends WebSecurityConfigurerAdapter {

// Aula 06
@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {
    private final UserDetailsService userDetailsService;
    private final TokenCreator tokenCreator;
    private final TokenConverter tokenConverter;
//  private final JwtConfiguration jwtConfiguration; //Aula 05 -> Removido aula 06

    // Aula 06
    public SecurityCredentialsConfig(JwtConfiguration jwtConfiguration,
                                     @Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService,
                                     TokenCreator tokenCreator, TokenConverter tokenConverter) {
        super(jwtConfiguration);
        this.userDetailsService = userDetailsService;
        this.tokenCreator = tokenCreator;
        this.tokenConverter = tokenConverter;
    }

    // Aula 04,05???
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
////    	super.configure(http);
//    	http
////    		.csrf().disable()
////    		.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
////    		.and()
////    			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
////			.and()
////    			.exceptionHandling().authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED))	
////			.and()
////				.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration))
//			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration, tokenCreator))
//			.authorizeRequests()
//				.antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
//				.antMatchers("course/admin/**").hasRole("ADMIN")
//				.anyRequest().authenticated();
//    }
    
    // Aula 06
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration, tokenCreator));
//        super.configure(http);
//    }  
    
    // Aula 07
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http
		    .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration, tokenCreator))
		    .addFilterAfter(new JwtTokenAuthorizationFilter(jwtConfiguration, tokenConverter), UsernamePasswordAuthenticationFilter.class);    	
        super.configure(http);
    }     
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
//        super.configure(auth);//Removido em alguma aula, não lembro
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
