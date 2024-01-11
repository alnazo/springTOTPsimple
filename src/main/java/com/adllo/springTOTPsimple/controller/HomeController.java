package com.adllo.springTOTPsimple.controller;

import com.adllo.springTOTPsimple.dto.UserDTO;
import com.adllo.springTOTPsimple.model.User;
import com.adllo.springTOTPsimple.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class HomeController {

    @Autowired
    private UserService userService;


    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("test", "hola mundo");
        return "index";
    }

    @GetMapping("/register")
    public String registerWeb(Model model) {
        model.addAttribute("newUser", new UserDTO());
        return "register";
    }

    @PostMapping("/register")
    public String register(UserDTO newUser) {
        User user = userService.findByEmail(newUser.getEmail());

        if (user != null) {
            return "redirect:/register?error";
        }

        userService.createUser(newUser);
        return "redirect:/login?success";
    }

}
