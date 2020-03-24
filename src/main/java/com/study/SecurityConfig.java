package com.study;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//@EnableWebSecurity springboot环境下可以不使用这个注解，而是将配置类继承‘’WebSecurityConfigurer或者实现‘WebSecurityConfigurer’，并直接标注 @Configuration即可。参考：WebSecurityConfiguration

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests(authorizeRequests -> authorizeRequests.antMatchers("/css/**", "/index").permitAll()
				.antMatchers("/user/**").hasRole("USER"))
				.formLogin(formLogin -> formLogin.loginPage("/login").failureUrl("/login-error"));
	}
	// @formatter:on

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
				.build();
		return new InMemoryUserDetailsManager(userDetails);
	}
}
