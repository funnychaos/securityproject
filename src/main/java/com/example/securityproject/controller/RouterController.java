package com.example.securityproject.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Description:
 * @Author: solar
 * @Date: 2020-02-11 23:58
 * @Version: 1.00
 */
@RestController
public class RouterController {


	@RequestMapping({"/index","/"})
	public String index(){
		return "index";
	}

	@RequestMapping("/toLogin")
	public String toLogin(){
		return "views/login";
	}

	@RequestMapping("/logout")
	public String logout(){
		return "logout success";
	}

	@RequestMapping("/level1/{id}")
	public String toLevel1(@PathVariable("id") int id){
		return "views/level1/"+id;
	}

	@RequestMapping("/level2/{id}")
	public String toLevel2(@PathVariable("id") int id){
		return "views/level2/"+id;
	}

	@RequestMapping("/level3/{id}")
	public String toLevel3(@PathVariable("id") int id){
		return "views/level3/"+id;
	}



}
