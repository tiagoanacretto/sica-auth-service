package br.com.sica.authservice.controllers;

import br.com.sica.authservice.dtos.MessageResponse;
import br.com.sica.authservice.dtos.SignupRequest;
import br.com.sica.authservice.filters.AuthTokenFilter;
import br.com.sica.authservice.models.ERole;
import br.com.sica.authservice.models.Role;
import br.com.sica.authservice.models.User;
import br.com.sica.authservice.repositories.RoleRepository;
import br.com.sica.authservice.repositories.UserRepository;
import br.com.sica.authservice.services.UserDetailsImpl;
import br.com.sica.authservice.services.UserDetailsServiceImpl;
import br.com.sica.authservice.utils.JwtUtils;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import br.com.sica.authservice.dtos.LoginRequest;
import br.com.sica.authservice.dtos.JwtResponse;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@OpenAPIDefinition(
        info = @Info(
                title = "sica-auth-service",
                description = "Serviço de autenticação para a POC da plataforma SICA",
                version = "1.0.0",
                contact = @Contact(name = "Tiago Anacretto", email = "tiago.anacretto@gmail.com")
        ))
@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class JwtAuthenticationController {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationController.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Operation(summary = "Autenticação de usuário", description = "Endpoint responsável pela autenticação de um usuário")
    @RequestMapping(value = "/signin", method = RequestMethod.POST)
    public ResponseEntity<?> autenticarUsuario(@Valid @RequestBody LoginRequest loginRequest) throws Exception {
        logger.info("Iniciando autenticarUsuario...");
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @Operation(summary = "Criação de usuário", description = "Endpoint responsável pela criação de novos usuários")
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.OPERADOR)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                Role adminRole = roleRepository.findByName(ERole.valueOf(role))
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(adminRole);
            });
        }
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @Operation(summary = "Validação de token", description = "Endpoint responsável por checar se uma chave JWT é autêntica")
    @RequestMapping(value = "/checktoken/{token}", method = RequestMethod.GET)
    public ResponseEntity<?> validarTokenAutenticacao(@PathVariable String token) throws Exception {
        logger.info("Iniciando check token...");
        boolean valido = jwtUtils.validateJwtToken(token);
        if (valido) {
            String username = jwtUtils.getUserNameFromJwtToken(token);
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
            List<String> roles = user.getRoles().stream().map(r -> r.getName().toString()).collect(Collectors.toList());
            return ResponseEntity.ok(new JwtResponse(token,
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    roles));
        }
        return ResponseEntity.badRequest().body(new MessageResponse("O token informado é inválido ou está expirado"));
    }

}
