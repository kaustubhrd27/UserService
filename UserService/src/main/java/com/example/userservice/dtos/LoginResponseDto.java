package com.example.userservice.dtos;

import com.example.userservice.Models.Token;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginResponseDto {
    private Token token;


}
