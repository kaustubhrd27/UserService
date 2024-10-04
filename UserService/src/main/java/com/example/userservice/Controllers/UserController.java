package com.example.userservice.Controllers;

import com.example.userservice.Exceptions.InvalidPasswordException;
import com.example.userservice.Exceptions.InvalidTokenException;
import com.example.userservice.Models.Token;
import com.example.userservice.Models.User;
import com.example.userservice.Services.UserService;
import com.example.userservice.dtos.SignUpRequestDto;
import com.example.userservice.dtos.LoginRequestDto;
import com.example.userservice.dtos.LoginResponseDto;
import com.example.userservice.dtos.LogOutRequestDto;
import com.example.userservice.dtos.UserDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;


    @PostMapping("/signup")  //localhost:8080/users/signup
    public UserDto signUp(@RequestBody SignUpRequestDto requestDto) throws JsonProcessingException {
        User user = userService.signUp(requestDto.getEmail(), requestDto.getPassword(), requestDto.getName());

        return fromUser(user);
    }

    @PostMapping("/login")
    public LoginResponseDto logIn(@RequestBody LoginRequestDto requestDto) throws InvalidPasswordException {
        Token token = userService.login(requestDto.getEmail(), requestDto.getPassword());

        return fromToken(token);
    }

    public LoginResponseDto fromToken(Token token) {
        LoginResponseDto dto = new LoginResponseDto();
        dto.setToken(token);
        return dto;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logOut(@RequestBody LogOutRequestDto requestDto){
        ResponseEntity<Void> responseEntity = null;
        try {
            userService.logOut(requestDto.getToken());
            responseEntity = new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception e) {
            System.out.println("Sorry Somethings went wrong");
            responseEntity = new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return responseEntity;
    }

    @PostMapping("validate/{tokenValue}")
    public UserDto validateToken(@PathVariable String tokenValue) throws InvalidTokenException {
        return fromUser(userService.validateToken(tokenValue));
    }

    public static UserDto fromUser(User user) {
        UserDto userDto = new UserDto();
        userDto.setName(user.getName());
        userDto.setEmail(user.getEmail());
        userDto.setEmailVerified(user.isEmailVerified());
        userDto.setRoles(user.getRoles());

        return userDto;
    }

    @GetMapping("/{id}")
    public String getUserDetails(@PathVariable("id") Long userId) {
        System.out.println("Recived The Request");
        return "Hello from user with id : " + userId;
    }
}
