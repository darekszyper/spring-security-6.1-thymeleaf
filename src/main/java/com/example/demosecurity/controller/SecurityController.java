package com.example.demosecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class SecurityController {

    @GetMapping("/not_secured/{id}")
    public String notSecured(@PathVariable String id, Model model) {
        model.addAttribute("id", id);
        return "not_secured";
    }

    @GetMapping("/secured")
    public String secured() {
        return "secured";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String processLogin() {
        return "login"; // Przekierowanie do widoku po zalogowaniu
    }

    @GetMapping("/default")
    public String defaultAfterLogin(HttpServletRequest request) {
        if (request.isUserInRole("ROLE_SUPER_USER")) {
            return "redirect:/admin";
        }
        return "redirect:/user";
    }
}
