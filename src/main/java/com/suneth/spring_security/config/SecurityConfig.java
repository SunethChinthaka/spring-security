package com.suneth.spring_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    /**
     * Configures the security filter chain, which defines the security settings for HTTP requests.
     *
     * @param httpSecurity The {@link HttpSecurity} object to configure the security settings.
     * @return A {@link SecurityFilterChain} that defines the security configuration.
     * @throws Exception If an error occurs while configuring security.
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity
                // Disable CSRF protection since we are using JWT for stateless authentication
                .csrf(customizer -> customizer.disable())
                // Define which requests are authorized without authentication and which require it
                .authorizeHttpRequests(request -> request
                        .requestMatchers("register", "login")
                        .permitAll()
                        .anyRequest().authenticated())
                // Enable HTTP basic authentication
                .httpBasic(Customizer.withDefaults())
                // Set session management to stateless as we are using JWT tokens instead of sessions
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Add a custom JWT filter before the UsernamePasswordAuthenticationFilter in the filter chain
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                // Build and return the SecurityFilterChain object
                .build();

    }

    /**
     * Configures the AuthenticationProvider to handle authentication logic.
     *
     * @return A configured {@link AuthenticationProvider} that uses a DAO for authentication.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        //looking for a class which implements AuthenticationProvider
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // Set the password encoder to bcrypt with a strength of 12 for hashing passwords
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        // Set the UserDetailsService to provide user-specific data during authentication
        provider.setUserDetailsService(userDetailsService);

        return provider;
    }

    /**
     * Provides an AuthenticationManager bean for handling authentication.
     *
     * @param configuration The {@link AuthenticationConfiguration} object used to obtain the AuthenticationManager.
     * @return An {@link AuthenticationManager} bean.
     * @throws Exception If an error occurs while creating the AuthenticationManager.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

}
