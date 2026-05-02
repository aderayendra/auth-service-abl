package id.aderayendra.authservice.controller;

import id.aderayendra.authservice.dto.AuthResponse;
import id.aderayendra.authservice.dto.LoginRequest;
import id.aderayendra.authservice.dto.RegisterRequest;
import id.aderayendra.authservice.model.User;
import id.aderayendra.authservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // Hapus field jwtUtil yang tidak digunakan
    // @Autowired
    // private JwtUtil jwtUtil;  // ← HAPUS INI

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            String token = authService.authenticate(loginRequest);
            User user = authService.getCurrentUser(loginRequest.getUsername());

            AuthResponse response = new AuthResponse(
                    token,
                    "Bearer",
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    user.getRole(),
                    86400000L // 24 jam dalam milliseconds
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Login gagal: " + e.getMessage());
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            User user = authService.register(registerRequest);
            return ResponseEntity.status(HttpStatus.CREATED).body(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                Boolean isValid = authService.validateToken(token);
                if (isValid) {
                    return ResponseEntity.ok(authService.getCurrentUser(authService.getUsernameFromToken(token)));
                }
            }
            return ResponseEntity.badRequest().body("Invalid token format");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token invalid");
        }
    }
}