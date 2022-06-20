package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.STUDENT;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityApplicationConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityApplicationConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                        .antMatchers("/api/**").hasRole(ADMIN.name())
                        .anyRequest().authenticated()
                )
                .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    protected UserDetailsService userDetailsService(){
        UserDetails anakin = User.builder()
                .username("anakin")
                .password(passwordEncoder.encode("0000"))
                .roles(STUDENT.name()) // ROLE_STUDENT
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("0000"))
                .roles(ADMIN.name())
                .build();
        return new InMemoryUserDetailsManager(
                anakin,
                admin
        );
    }
}
