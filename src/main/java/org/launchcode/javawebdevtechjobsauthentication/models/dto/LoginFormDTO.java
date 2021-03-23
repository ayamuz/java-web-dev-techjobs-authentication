package org.launchcode.javawebdevtechjobsauthentication.models.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class LoginFormDTO {


        @NotNull
        @NotBlank
        @Size(min = 3, max = 18, message = "Make sure your username is between 3 and 18 characters.")
        private String username;

        @NotNull
        @NotBlank
        @Size(min = 8, max = 30, message = "Choose another password; it mus be between 6 and 30 characters")
        private String password;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

    }

