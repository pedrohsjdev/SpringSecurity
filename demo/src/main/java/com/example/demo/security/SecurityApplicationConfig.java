package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.demo.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true) // For use the @PreAutorize annotation
public class SecurityApplicationConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public SecurityApplicationConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .authorizeHttpRequests((authz) -> authz
                        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                        .antMatchers("/api/**").hasRole(STUDENT.name())
                        .anyRequest().authenticated()
                );
//                .formLogin()
//                    .loginPage("/login").permitAll()
//                    .defaultSuccessUrl("/courses", true)
//                    .passwordParameter("password") // deixar igual o default, se quiser mudar o parametro do forma, so alterar aqui
//                    .usernameParameter("username")
//                .and()
//                    .rememberMe().tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))// defaults for 2 weeks
//                    .key("securekeyalternativefordefaults")
//                    .rememberMeParameter("remember-me")
//                .and()
//                    .logout()
//                    .logoutUrl("/logout")
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID", "remember-me")
//                    .logoutSuccessUrl("/login");

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
