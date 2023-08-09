package com.example.demosecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
// add dependency thymeleaf security

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager get() {
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("password"))
                .roles("SUPER_USER")
                .build();
        return new InMemoryUserDetailsManager(List.of(user, admin));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize// authorize requests
                        .requestMatchers("/admin").hasRole("SUPER_USER")// show admin page only for SUPER_USER
                        .requestMatchers("/user").hasRole("USER")// show user page only for USER
                        .requestMatchers("/not_secured/**").permitAll()// show not_secured page for all
                        .anyRequest().authenticated()// show secured page for all authenticated users
                )
                .formLogin(formLogin -> formLogin// configure login form
                        .loginPage("/login")// address to which we will be redirected if we are not logged in
                        .usernameParameter("username")// set username parameter name in login form input
                        .passwordParameter("password")// set password parameter name in login form input
                        .defaultSuccessUrl("/default")// address to which we will be redirected after successful login
                        .loginProcessingUrl("/login")// address to which the login form will be sent
                        .permitAll()// allow access to the login page for all
                )
                .logout(logout -> logout// configure logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))// address to which the logout form will be sent
                        .logoutSuccessUrl("/login")// address to which we will be redirected after successful logout
                        .deleteCookies("JSESSIONID")// delete cookies after logout
                        .invalidateHttpSession(true)// invalidate session after logout
                )
                .rememberMe(Customizer.withDefaults());// enable remember me option in login form (cookies) - default 2 weeks

        return http.build();// return SecurityFilterChain
    }
}
