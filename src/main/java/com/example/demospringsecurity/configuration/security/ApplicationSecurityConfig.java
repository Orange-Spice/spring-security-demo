package com.example.demospringsecurity.configuration.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.demospringsecurity.auth.services.ApplicationUserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			//Se deshabilita CSRF cuando no se están haciendo request desde un cliente navegador
			.csrf().disable()
			//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			//.and()
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
			.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
			//El orden de los antMatchers importa
//			.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
//			.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
//			.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
//			.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
			.anyRequest()
			.authenticated()
			.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.defaultSuccessUrl("/courses", true)
				.usernameParameter("username")
				.passwordParameter("password")
			.and()
			.rememberMe()
				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))//Sobrescribe la duración de la cookie remember-me
				//.key("averysecurekey");//clave para hashear la cookie
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))//Esto es porque el CSRF está deshabilitado, eliminar cuando se activa el csrf
				.clearAuthentication(true)
				.invalidateHttpSession(false)
				.deleteCookies("JSESSIONID","remember-me")
				.logoutSuccessUrl("/login");
			
	}

	/**
	 * Método para obtener los usuarios (BDD, LDAP, In-Memory, etc)
	 */
//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//		UserDetails annaSmithUser =  User.builder()
//				.username("annasmith")
//				.password(passwordEncoder.encode("1234"))
//				//.roles(ApplicationUserRole.STUDENT.name())//La clase User le añade el prefijo ROLE_
//				.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
//				.build();
//		
//		UserDetails lindaUser =  User.builder()
//				.username("linda")
//				.password(passwordEncoder.encode("1234"))
//				//.roles(ApplicationUserRole.ADMIN.name())//La clase User le añade el prefijo ROLE_
//				.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
//				.build();
//		
//		UserDetails tomUser =  User.builder()
//				.username("tom")
//				.password(passwordEncoder.encode("1234"))
//				//.roles(ApplicationUserRole.ADMINTRAINEE.name())//La clase User le añade el prefijo ROLE_
//				.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
//				.build();
//		
//		return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
//	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
}
