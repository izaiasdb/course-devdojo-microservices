package br.com.idb.idbauth.filter;

/*
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import br.gov.ce.sap.sapcore.model.UsuarioEntity;
import br.gov.ce.sap.sapcore.property.JwtConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilterAula05 extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;
	private final JwtConfiguration jwtConfiguration;
	
	@Override
	@SneakyThrows // Encapsula em exceção do tipo runtime
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		log.info("Attempting authentication. . .");
		UsuarioEntity usuario = new ObjectMapper().readValue(request.getInputStream(), UsuarioEntity.class);

		if (usuario == null)
			throw new UsernameNotFoundException("Unable to retrieve the username or password");

		log.info(
				"Creating the authentication object for the user '{}' and calling UserDetailServiceImpl loadUserByUsername",
				usuario.getUsername());

		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				usuario.getUsername(), usuario.getPassword(), emptyList());

		usernamePasswordAuthenticationToken.setDetails(usuario);

		return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
	}

	@Override
	@SneakyThrows
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) {
		log.info("Authentication was successful for the user '{}', generating JWE token", auth.getName());

		SignedJWT signedJWT = createSignedJWT(auth);
		String encryptedToken = encrypted(signedJWT);

		log.info("Token generated successfully, adding it to the response header");

		response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfiguration.getHeader().getName());
		response.addHeader(jwtConfiguration.getHeader().getName(),
				jwtConfiguration.getHeader().getPrefix() + encryptedToken);
	}
	
	@SneakyThrows
	private SignedJWT createSignedJWT(Authentication auth) {
		log.info("Starting to create signed JWT");

		UsuarioEntity applicationUser = (UsuarioEntity) auth.getPrincipal();
		JWTClaimsSet jwtClaimSet = createJWTClaimSet(auth, applicationUser);

		KeyPair rsaKeys = generateKeyPair();
		log.info("Building JWK from the RSA Keys");

		JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build(), jwtClaimSet);
        		
		log.info("Signing the token with the private RSA key");

		RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());
		signedJWT.sign(signer);

		log.info("Serialized token '{}'", signedJWT.serialize());
		return signedJWT;
	}	
	
	private JWTClaimsSet createJWTClaimSet(Authentication auth, UsuarioEntity applicationUser) {
		log.info("Creating the JWTClaimsSet Object for '{}'", applicationUser);

		return new JWTClaimsSet.Builder()
				.subject(applicationUser.getUsername())
				.claim("authorities", auth.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority).collect(toList()))
				.issuer("https://www.sap.ce.gov.br").issueTime(new Date())
				.expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
				.build();
	}
	
	@SneakyThrows
	private KeyPair generateKeyPair() {
		log.info("Generating RSA 2048 bitd keys");

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);

		return generator.genKeyPair();
	}
	
	private String encrypted(SignedJWT signedJWT) throws JOSEException {
		log.info("Starting the encrypt Token method");

		DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(signedJWT));

		log.info("Encrypting token with system's private key");
		jweObject.encrypt(directEncrypter);

		log.info("Token encrypted");

		return jweObject.serialize();
	}
}
*/