package br.com.franca.encriptar.senha.encriptarsenhausuario.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.franca.encriptar.senha.encriptarsenhausuario.data.DetalheUsuarioData;
import br.com.franca.encriptar.senha.encriptarsenhausuario.model.UsuarioModel;

public class JWTAutenticarFilter extends UsernamePasswordAuthenticationFilter {
	
	public static final int TOKEN_EXPIRACAO = 600_000;
	
	public static final String TOKEN_SENHA = "44e38d94-bcbe-42c6-9261-55febc2dd37a";
	
	private final AuthenticationManager authenticationManager;
	
	public JWTAutenticarFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, 
																	 HttpServletResponse response) throws AuthenticationException {
		try {
			UsuarioModel usuario = new ObjectMapper()
					.readValue(request.getInputStream(), UsuarioModel.class);
			
			return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					usuario.getLogin(),
					usuario.getPassword(),
					new ArrayList<>()));
		} catch (IOException e) {
			throw new RuntimeException("Falha ao autenticar o usuário(a).", e);
		}
		
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, 
																HttpServletResponse response, 
																FilterChain chain,
																Authentication authResult) throws IOException, ServletException {
		
		DetalheUsuarioData usuarioData = (DetalheUsuarioData) authResult.getPrincipal();
		
		String token = JWT.create().
				withSubject(usuarioData.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRACAO))
				.sign(Algorithm.HMAC512(TOKEN_SENHA));
				
		response.getWriter().write(token);
		response.getWriter().flush();
	}

}
