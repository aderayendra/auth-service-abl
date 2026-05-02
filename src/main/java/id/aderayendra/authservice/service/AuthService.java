package id.aderayendra.authservice.service;

import id.aderayendra.authservice.dto.LoginRequest;
import id.aderayendra.authservice.dto.RegisterRequest;
import id.aderayendra.authservice.model.User;
import id.aderayendra.authservice.repository.UserRepository;
import id.aderayendra.authservice.security.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtUtil jwtUtil;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public String authenticate(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByUsername(userDetails.getUsername()).orElse(null);

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", userDetails.getAuthorities().iterator().next().getAuthority());
        if (user != null) {
            claims.put("userId", user.getId());
        }

        return jwtUtil.generateTokenWithClaims(claims, userDetails.getUsername());
    }

    public User register(RegisterRequest registerRequest) {
        // Cek apakah username sudah ada
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new RuntimeException("Username sudah terdaftar!");
        }

        // Cek apakah email sudah ada
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new RuntimeException("Email sudah terdaftar!");
        }

        // Buat user baru
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setFullName(registerRequest.getFullName());
        user.setRole(registerRequest.getRole());
        user.setIsActive(true);

        return userRepository.save(user);
    }

    public User getCurrentUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User tidak ditemukan"));
    }

    public Boolean validateToken(String token) {
        return jwtUtil.validateToken(token);
    }

    public String getUsernameFromToken(String token) {
        return jwtUtil.extractUsername(token);
    }
}