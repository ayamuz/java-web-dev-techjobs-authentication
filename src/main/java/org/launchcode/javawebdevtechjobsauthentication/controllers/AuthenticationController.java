package org.launchcode.javawebdevtechjobsauthentication.controllers;

import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.LoginFormDTO;
import org.launchcode.javawebdevtechjobsauthentication.models.dto.RegisterFormDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.Optional;

public class AuthenticationController {
@Autowired
UserRepository userRepository;
    //Static variable for the session key
    private static final String userSessionKey = "user";

    //Method to get the user info from the session
    public User getUserFromSession(HttpSession session) {
        Integer userId = (Integer) session.getAttribute(userSessionKey);
        if (userId == null) {
            return null;
        }

        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            return null;
        }

        return user.get();
    }
    //Method to set the user in the session
    private static void setUserInSession(HttpSession session, User user) {
        session.setAttribute(userSessionKey, user.getId());
    }

    @GetMapping("/register")
    public String displayRegistrationForm(Model model) {
        model.addAttribute(new RegisterFormDTO());
        model.addAttribute("title", "Register");
        return "register";
    }
    @PostMapping("/register")
    public String processRegistrationForm(@ModelAttribute @Valid RegisterFormDTO registerFormDTO,
                                          Errors errors, HttpServletRequest request,
                                          Model model) {

        if (errors.hasErrors()) {
            model.addAttribute("title", "Register");
            return "register";
        }

        User existingUser = userRepository.findByUsername(registerFormDTO.getUsername());

        if (existingUser != null) {
            //This is a custom error
            errors.rejectValue("username", "username.alreadyexists", "This username is already taken, please choose anew one");
            model.addAttribute("title", "Register");
            return "register";
        }
        //This password was set in LoginFormDTO
        String password = registerFormDTO.getPassword();
       //This password was set in RegisterFormDTO that EXTENDS LoginFormDTO
        String verifyPassword = registerFormDTO.getVerifyPassword();
        if (!password.equals(verifyPassword)) {
            errors.rejectValue("password", "passwords.mismatch", "Passwords do not match");
            model.addAttribute("title", "Register");
            return "register";
        }
        //1. Create new user
        User newUser = new User(registerFormDTO.getUsername(), registerFormDTO.getPassword());
       //2. Save new user to the database
        userRepository.save(newUser);
       //3. Create new session for the user
        setUserInSession(request.getSession(), newUser);
        //4. Redirect to homepage
        return "redirect:";
    }
// Handle the login data
@GetMapping("/login")
public String displayLoginForm(Model model) {
    model.addAttribute(new LoginFormDTO());
    model.addAttribute("title", "Log In");
    return "login";
}
    @PostMapping("/login")
    public String processLoginForm(@ModelAttribute @Valid LoginFormDTO loginFormDTO,
                                   Errors errors, HttpServletRequest request,
                                   Model model) {

        if (errors.hasErrors()) {
            model.addAttribute("title", "Log In");
            return "login";
        }
        //Finds user on the database
        User theUser = userRepository.findByUsername(loginFormDTO.getUsername());
        //Throw custom error if there's no match for this user
        if (theUser == null) {
            errors.rejectValue("username", "user.invalid", "The username doesn't exist");
            model.addAttribute("title", "Log In");
            return "login";
        }
        //Handle the password SUBMITTED through the login form
        String password = loginFormDTO.getPassword();
        //Compares the password form the form
        if (!theUser.isMatchingPassword(password)) {
            //Send an error if passwords do not match
            errors.rejectValue("password", "password.invalid", "Invalid password");
            model.addAttribute("title", "Log In");
            return "login";
        }
        //Create a new session for the user
        setUserInSession(request.getSession(), theUser);
        //Back to home page
        return "redirect:";
    }
}