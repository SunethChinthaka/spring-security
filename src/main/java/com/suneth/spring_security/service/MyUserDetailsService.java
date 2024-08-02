package com.suneth.spring_security.service;

import com.suneth.spring_security.model.UserPrincipal;
import com.suneth.spring_security.model.Users;
import com.suneth.spring_security.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users user = userRepo.findByUsername(username);

        if (user == null) {
            System.out.println("User not found: ");
            throw new UsernameNotFoundException("User not found");
        }
        return new UserPrincipal(user);
    }
}