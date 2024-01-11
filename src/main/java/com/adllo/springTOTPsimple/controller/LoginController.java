package com.adllo.springTOTPsimple.controller;

import com.adllo.TOTP;
import com.adllo.springTOTPsimple.enums.Role;
import com.adllo.springTOTPsimple.model.User;
import com.adllo.springTOTPsimple.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;

@RequestMapping("/login")
@Controller
@Slf4j
public class LoginController {

    private String homeRedirect = "redirect:/";
    private String codeRedirect = "redirect:/login/auth/code";

    @Autowired
    private UserService userService;

    @GetMapping("")
    public String loginWeb() {
        return "login";
    }

    @GetMapping("/auth/active")
    public String activeCodeLogin(HttpServletRequest request, Model model) {
        if (request.isUserInRole("MFA_ACTIVE")) {
            return codeRedirect;
        }
        User user = userService.findByEmail(request.getUserPrincipal().getName());
        String qr = TOTP.qrImageUrl("MFA Accenture Test: " + user.getEmail(), user.getSecret());

        model.addAttribute("qr", qr);

        return "active";
    }

    @PostMapping("/auth/active")
    public String verifyCodeLogin(String code, HttpServletRequest request) {
        User user = userService.findByEmail(request.getUserPrincipal().getName());

        try {
            String cod = TOTP.generateCurrentNumberString(user.getSecret());
            if (cod.equals(code)) {
                userService.addAuthority(user, Role.MFA_ACTIVE);
                return homeRedirect;
            }
        } catch (GeneralSecurityException e) {
            log.error("Error generar codigo actual de: " + user.getEmail());
        }

        return "redirect:/login/auth/active?error";
    }

    @GetMapping("/auth/code")
    public String getCodeLogin() {
        return "code";
    }

    @PostMapping("/auth/code")
    public String authCodeLogin(String code, HttpServletRequest request) {
        User user = userService.findByEmail(request.getUserPrincipal().getName());

        try {
            String cod = TOTP.generateCurrentNumberString(user.getSecret());
            if (cod.equals(code)) {
                return homeRedirect;
            }
        } catch (GeneralSecurityException e) {
            log.error("Error generar codigo com.accenture.TOTP de: " + user.getEmail());
        }

        return codeRedirect + "?error";
    }


}
