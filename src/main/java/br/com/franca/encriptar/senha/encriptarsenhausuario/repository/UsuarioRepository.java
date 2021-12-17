package br.com.franca.encriptar.senha.encriptarsenhausuario.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import br.com.franca.encriptar.senha.encriptarsenhausuario.model.UsuarioModel;

public interface UsuarioRepository extends JpaRepository<UsuarioModel, Integer> {

	public Optional<UsuarioModel> findByLogin(String Login);
	
}
