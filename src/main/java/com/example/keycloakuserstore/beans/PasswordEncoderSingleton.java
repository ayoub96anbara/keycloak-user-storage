package com.example.keycloakuserstore.beans;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordEncoderSingleton {

    private static PasswordEncoder single_instance = null;

    private PasswordEncoderSingleton()
    {
    }

    public static PasswordEncoder getInstance()
    {
        if (single_instance == null) {
            single_instance = new BCryptPasswordEncoder();
        }
        return single_instance;
    }

}
