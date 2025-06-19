package org.assets.jwtdemo.config;

import org.assets.jwtdemo.model.Role;
import org.assets.jwtdemo.model.User;
import org.assets.jwtdemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Create default admin user if not exists
        if (!userRepository.existsByUsername("admin")) {
            User admin = new User("admin", passwordEncoder.encode("admin123"), "admin@example.com", Role.ADMIN);
            userRepository.save(admin);
            System.out.println("Default admin user created: admin/admin123");
        }

        // Create default user if not exists
        if (!userRepository.existsByUsername("user")) {
            User user = new User("user", passwordEncoder.encode("user123"), "user@example.com", Role.USER);
            userRepository.save(user);
            System.out.println("Default user created: user/user123");
        }
    }
} 