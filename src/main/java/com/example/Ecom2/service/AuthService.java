package com.example.Ecom2.service;


import com.example.Ecom2.payload.LoginDto;
import com.example.Ecom2.payload.RegisterDto;

public interface AuthService {
    String login(LoginDto loginDto);
    String register(RegisterDto registerDto);
}
