package com.study;

import java.lang.reflect.ParameterizedType;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class Readme {

	// key class
	void readme() {
		// ServletSecurity
		// SpringServletContainerInitializer
		// AbstractSecurityWebApplicationInitializer
		// DelegatingFilterProxy
		// WebSecurityConfigurerAdapter
		// WebSecurityConfiguration
		// FilterChainProxy known as the Spring Security Filter Chain
		// * (springSecurityFilterChain). The springSecurityFilterChain is the {@link
		// Filter} that
		// * the {@link DelegatingFilterProxy} delegates to.
		
		//TODO SecurityAutoConfiguration  WebSecurityConfiguration
		//SecurityContextHolder  UserDetailsService UserDetails
		//Authentication AuthenticationManager
		
		//AbstractSecurityInterceptor
		//SecurityContextPersistenceFilter
		
		//TODO Access-Control (Authorization) in Spring Security
		//AccessDecisionManager
		
		//AuthenticationProvider  DaoAuthenticationProvider
		//LinkedBlockingQueue
		
		//TODO 
		//ProviderManager  JdbcDaoImpl
		//AuthenticationManagerBuilder
		//AccessDecisionManager
		//GrantedAuthority
	}

	public static void main(String[] args) {
		// Stream
		Function<String, Integer> func = in -> {
			return Integer.parseInt(in);
		};
		Arrays.asList(func.getClass()
				.getGenericSuperclass())
		.forEach(x->{
			System.out.println(x instanceof ParameterizedType);
			System.out.println(x.getTypeName());
		});
		System.out.println(func.getClass().getName());
		
		List<String> list=Arrays.asList("1","2");
		
		System.out.println(convert(list, func));
	}
	
	static <I,O> List<O> convert(List<I> in,Function<I, O> func){
		return in.stream().map(func).collect(Collectors.toList());
	}
}
