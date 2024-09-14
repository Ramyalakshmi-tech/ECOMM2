package com.example.Ecom2.service.Impl;

import com.example.Ecom2.entity.Role;
import com.example.Ecom2.entity.User;
import com.example.Ecom2.exception.BlogAPIException;
import com.example.Ecom2.payload.LoginDto;
import com.example.Ecom2.payload.RegisterDto;
import com.example.Ecom2.repository.RoleRepository;
import com.example.Ecom2.repository.UserRepository;
import com.example.Ecom2.security.JwtTokenProvider;
import com.example.Ecom2.service.AuthService;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class AuthServiceImpl implements AuthService {
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private JwtTokenProvider jwtTokenProvider;

    public AuthServiceImpl(AuthenticationManager authenticationManager, UserRepository userRepository,
                           RoleRepository roleRepository, PasswordEncoder passwordEncoder,JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider=jwtTokenProvider;
    }

    @Override
    public String login(LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsernameOrEmail(), loginDto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token=jwtTokenProvider.generateToken(authentication);
        return token;
    }

    @Override
    @Transactional
    public String register(RegisterDto registerDto) {
        logger.info("Registering user with username: {}", registerDto.getUsername());



        User user = new User();
        user.setEmail(registerDto.getEmail());
        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));

        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName("ROLE_USER").orElseThrow(() ->
                new BlogAPIException(HttpStatus.BAD_REQUEST, "Role not found"));
        roles.add(userRole);
        user.setRoles(roles);

        userRepository.save(user); // Ensure this line is present to save the user
        logger.info("User registered successfully: {}", user);

        return "User registered successfully";
    }
}
