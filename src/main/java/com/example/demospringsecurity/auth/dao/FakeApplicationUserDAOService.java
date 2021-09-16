package com.example.demospringsecurity.auth.dao;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.example.demospringsecurity.auth.model.ApplicationUser;
import com.example.demospringsecurity.configuration.security.ApplicationUserRole;
import com.google.common.collect.Lists;

@Repository("fake")
public class FakeApplicationUserDAOService implements ApplicationUserDAO{
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDAOService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers() {
		
		ApplicationUser annaSmithUser = new ApplicationUser(ApplicationUserRole.STUDENT.getGrantedAuthorities(), passwordEncoder.encode("1234"), "annasmith", true, true, true, true);
		ApplicationUser lindaUser = new ApplicationUser(ApplicationUserRole.ADMIN.getGrantedAuthorities(), passwordEncoder.encode("1234"), "linda", true, true, true, true);
		ApplicationUser tomUser = new ApplicationUser(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(), passwordEncoder.encode("1234"), "tom", true, true, true, true);
		
		List<ApplicationUser> applicationUsers = Lists.newArrayList(annaSmithUser, lindaUser, tomUser);
		
		return applicationUsers;
	}
	
}
