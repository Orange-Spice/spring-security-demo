package com.example.demospringsecurity.auth.dao;

import java.util.Optional;

import com.example.demospringsecurity.auth.model.ApplicationUser;

public interface ApplicationUserDAO {

	Optional<ApplicationUser> selectApplicationUserByUsername(String username);
	
}
