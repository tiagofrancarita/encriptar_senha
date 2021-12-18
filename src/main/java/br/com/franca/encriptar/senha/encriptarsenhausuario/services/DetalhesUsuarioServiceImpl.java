package br.com.franca.encriptar.senha.encriptarsenhausuario.services;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import br.com.franca.encriptar.senha.encriptarsenhausuario.data.DetalheUsuarioData;
import br.com.franca.encriptar.senha.encriptarsenhausuario.model.UsuarioModel;
import br.com.franca.encriptar.senha.encriptarsenhausuario.repository.UsuarioRepository;

@Component
public class DetalhesUsuarioServiceImpl implements UserDetailsService {

	private final UsuarioRepository repository;
	
	
	public DetalhesUsuarioServiceImpl(UsuarioRepository repository) {
		this.repository = repository;
		
	}
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Optional<UsuarioModel> usuario = repository.findByLogin(username);
		
		if (usuario.isEmpty()) {
			throw new UsernameNotFoundException("Usuario [" + username + "] não encontrado!");
		}
		
		return new DetalheUsuarioData(usuario);
	}

}
