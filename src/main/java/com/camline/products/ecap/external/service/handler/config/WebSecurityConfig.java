/**
 * 
 */
package com.camline.products.ecap.external.service.handler.config;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * @author smallika
 *
 */
//@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	@Value("${spring.security.user.name}")
	private String username;
	
	@Value("${spring.security.user.password}")
	private String password;
	
	
	@Value("${spring.security.user.roles}")
	private String role;
	
	@Autowired
	private AuthenticationEntryPoint authEntryPoint;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests()
				.anyRequest().authenticated()
				.and().httpBasic()
				//.authenticationEntryPoint((request,response,exp)->response.sendError(HttpServletResponse.SC_UNAUTHORIZED));
				.authenticationEntryPoint(authEntryPoint)
				;
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser(username).password(password).roles(role);
	}
	
	 @Bean
	 public BCryptPasswordEncoder bCryptPasswordEncoder()
	 {
		 return new BCryptPasswordEncoder();
	 }
}
