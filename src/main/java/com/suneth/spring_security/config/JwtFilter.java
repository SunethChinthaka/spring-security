package com.suneth.spring_security.config;

import com.suneth.spring_security.service.JWTService;
import com.suneth.spring_security.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    ApplicationContext context;

    /**
     * This method filters each incoming HTTP request to check for a valid JWT token in the Authorization header.
     * If a valid token is found, it sets up the security context for the request, allowing authenticated access.
     *
     * @param request The incoming HTTP request.
     * @param response The outgoing HTTP response.
     * @param filterChain The filter chain to continue processing the request.
     * @throws ServletException If an error occurs during filtering.
     * @throws IOException If an I/O error occurs during filtering.
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Extract the Authorization header from the request
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        // Check if the Authorization header contains a Bearer token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // Extract the token by removing the "Bearer " prefix
            token = authHeader.substring(7);
            // Extract the username from the token using the JWTService
            username = jwtService.extractUsername(token);
        }

        // If a username was extracted and the user is not already authenticated
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Load the user details from the database using the MyUserDetailsService
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(username);

            // Validate the token against the user details
            if (jwtService.validateToken(token, userDetails)) {
                // Create an authentication token with the user's details
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Set additional authentication details from the request
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authenticated user in the security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Continue processing the request through the filter chain
        filterChain.doFilter(request, response);
    }
}
