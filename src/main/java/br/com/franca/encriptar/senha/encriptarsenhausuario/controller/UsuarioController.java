package br.com.franca.encriptar.senha.encriptarsenhausuario.controller;

import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.franca.encriptar.senha.encriptarsenhausuario.model.UsuarioModel;
import br.com.franca.encriptar.senha.encriptarsenhausuario.repository.UsuarioRepository;

@RestController
@RequestMapping("/api/usuario")
public class UsuarioController {
	
	private final UsuarioRepository repository;
	
	private final PasswordEncoder encoder;
	
	public UsuarioController(UsuarioRepository repository, PasswordEncoder encoder) {
		this.repository = repository;
		this.encoder = encoder;
	}
	
	@GetMapping("/listarTodos")
	public ResponseEntity<List<UsuarioModel>> listarTodos(){
		return ResponseEntity.ok(repository.findAll());
	}
	
	@PostMapping("/salvar")
	public ResponseEntity<UsuarioModel> salvar (@RequestBody UsuarioModel usuario){
		
		usuario.setPassword(encoder.encode(usuario.getPassword()));
		
		return ResponseEntity.ok(repository.save(usuario));
	}
	
	@GetMapping("/validarSenha")
	public ResponseEntity<Boolean> validarSenha(
																		@RequestParam String login,
																		@RequestParam String password) {
		
		Optional<UsuarioModel> optUsuario = repository.findByLogin(login);
		
		if(optUsuario.isEmpty()) {
			
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
		}
		
		UsuarioModel usuario = optUsuario.get();
		boolean valid = encoder.matches(password, usuario.getPassword());
		
		HttpStatus status = (valid) ? HttpStatus.OK : HttpStatus.UNAUTHORIZED;
		
		return ResponseEntity.status(status).body(valid);
	}
}
