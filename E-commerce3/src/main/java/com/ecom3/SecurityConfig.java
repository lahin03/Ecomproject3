package com.ecom3;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ecom3.jwt.AuthEntryPointJwt;
import com.ecom3.jwt.AuthTokenFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	
	@Autowired
	DataSource dataSource;
	
	@Autowired
	private AuthEntryPointJwt unauthorizedHnadler;
	
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
		http.authorizeHttpRequests(authorizeRequests ->
			authorizeRequests.requestMatchers("/signin/**").permitAll()
				.requestMatchers("/h2-console/**").permitAll()
				.anyRequest().authenticated());
		http.sessionManagement(session
				-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		//http.formLogin(withDefaults());
		http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHnadler));
		//http.httpBasic();
		http.headers(headers ->
				headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
		http.csrf(csrf -> csrf.disable());
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
		return http.build();
	}
	

	
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}
	
	@Bean
	public CommandLineRunner initData (JdbcUserDetailsManager userDetailsManager) {
		return args -> {
			JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsManager;
			UserDetails user1 = User.withUsername("user1")
				.password(passwordEncoder().encode("password1"))
				.roles("USER")
				.build();
			UserDetails admin = User.withUsername("admin")
					.password(passwordEncoder().encode("adminpassword"))
					.roles("ADMIN")
					.build();
					
			//JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager();
			userDetailsManager.createUser(user1);
			userDetailsManager.createUser(admin);
		};
	}
	
	
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
		return builder.getAuthenticationManager();
	}
}
