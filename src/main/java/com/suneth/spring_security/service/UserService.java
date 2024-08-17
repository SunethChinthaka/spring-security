package com.suneth.spring_security.service;

import com.suneth.spring_security.model.Users;
import com.suneth.spring_security.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTService jwtService;

    // Password encoder instance for hashing user passwords
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    /**
     * Registers a new user by encoding the user's password and saving the user entity.
     *
     * @param user The user entity containing the user's details.
     * @return The saved user entity.
     */
    public Users register(Users user) {
        // Encode the user's password before saving
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    /**
     * Verifies the user's credentials. If the credentials are valid, generates a JWT token.
     *
     * @param user The user entity containing the user's credentials.
     * @return A JWT token if authentication is successful, otherwise "failed".
     */
    public String verify(Users user) {
        // Authenticate the user using the provided credentials
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        // If authentication is successful, generate and return a JWT token
        if (authentication.isAuthenticated())
            return jwtService.generateToken(user.getUsername());

        return "failed";
    }
}
