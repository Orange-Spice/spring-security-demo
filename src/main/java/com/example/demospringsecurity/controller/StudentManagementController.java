package com.example.demospringsecurity.controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demospringsecurity.model.Student;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("management/api/v1/students")
@Slf4j
public class StudentManagementController {

	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "James Bond"),
			new Student(2, "Maria Jones"),
			new Student(3, "Anna Smith"));
	
	@GetMapping
	@PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
	public List<Student> getAllStudents(){
		log.info("getAllStudents");
		return STUDENTS;
	}
	
	@PostMapping
	@PreAuthorize("hasAuthority('course:write')")
	public void registerNewStudent(@RequestBody Student student) {
		log.info("registerNewStudent");
		log.info("student:"+student);
	}
	
	@DeleteMapping(path = "/{studentId}")
	@PreAuthorize("hasAuthority('course:write')")
	public void deleteStudent(@PathVariable("studentId") Integer studentId) {
		log.info("deleteStudent");
		log.info("studentId:"+studentId);
	}
	
	@PutMapping(path = "/{studentId}")
	@PreAuthorize("hasAuthority('course:write')")
	public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
		log.info("updateStudent");
		log.info(String.format("%s %s", studentId, student));
	}
	
}
