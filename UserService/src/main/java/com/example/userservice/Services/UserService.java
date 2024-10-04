package com.example.userservice.Services;

import com.example.userservice.Exceptions.InvalidPasswordException;
import com.example.userservice.Exceptions.InvalidTokenException;
import com.example.userservice.Models.Token;
import com.example.userservice.Models.User;
import com.example.userservice.Repositories.TokenRepository;
import com.example.userservice.Repositories.UserRepository;
import com.example.userservice.configs.KafkaProducerClient;
import com.example.userservice.dtos.SendEmailDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Service
public class UserService {

    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private TokenRepository tokenRepository;
    private KafkaProducerClient kafkaProducerClient;
    private ObjectMapper objectMapper;

    public UserService(TokenRepository tokenRepository,
                       UserRepository userRepository,
                       BCryptPasswordEncoder bCryptPasswordEncoder,
                       KafkaProducerClient kafkaProducerClient,
                       ObjectMapper objectMapper) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.kafkaProducerClient = kafkaProducerClient;
        this.objectMapper = objectMapper;
    }

    public User signUp(String email, String password, String name) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser .isPresent()) {
            //user is already present in DB, so no need to signUp
            return optionalUser .get();
        }

        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));

        // once the signup is complete , send a msg to kafka for sending an email to user
        SendEmailDto sendEmailDto = new SendEmailDto();
        sendEmailDto.setTo(user.getEmail());
        sendEmailDto.setFrom("admin@scaler.com");
        sendEmailDto.setSubject("User Registration");
        sendEmailDto.setBody("Thanks For Registration");

        try {
            kafkaProducerClient.sendEvent("sendEmail",objectMapper.writeValueAsString(sendEmailDto));
        } catch (JsonProcessingException e) {
            System.out.println("Something went wrong while sending msg to kafka");

        }
        return userRepository.save(user);
    }

    public Token login(String email, String password) throws InvalidPasswordException {
        /*
        * 1.Check if user exists with given email id
        * 2.if not throw exception or return the user to login page
        * 3.if yes , then compare the password with the password stored in DB
        * 4.if password matches then login is successful and return new token
        *
        * */
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            //it is meaning that this particular user is not present in the db
            return null;
        }

        User user = optionalUser.get();
        if (!bCryptPasswordEncoder.matches(password, user.getHashedPassword())) {
            throw new InvalidPasswordException("Please Enter the correct Password");
        }

        // now login is successful, system should generate a new ticket
        Token token = generateToken(user);
        Token savedToken = tokenRepository.save(token);

        return savedToken;
    }

    private Token generateToken(User user) {
        //Here we are setting the expiry date for our token
        LocalDate currentTime = LocalDate.now();
        LocalDate thirtyDaysFromCurrentTime = currentTime.plusDays(30);

        Date expiryDate = Date.from(thirtyDaysFromCurrentTime.atStartOfDay(ZoneId.systemDefault()).toInstant());

        Token token = new Token();
        token.setExpiryAt(expiryDate);

        //so basically token value is a randomly generated string of 128 characters --- > standard
        token.setValue(RandomStringUtils.randomAlphanumeric(128));
        token.setUser(user);
        return token;
    }

    public void logOut(String tokenValue) throws InvalidTokenException {
        //first we should check the given token is valid or not and also we need to check is_deleted == false
        Optional<Token> optionalToken = tokenRepository.findByValueAndIsDeleted(tokenValue,false);

        if (optionalToken.isEmpty()) {
            //Throw an exception
            throw new InvalidTokenException("Invalid Token Passed");
        }

        Token token = optionalToken.get();
        token.setDeleted(true);

        tokenRepository.save(token);
        return;
    }

    public User validateToken(String tokenValue) throws InvalidTokenException {
        Optional<Token> optionalToken = tokenRepository.findByValueAndIsDeleted(tokenValue,false);

        if (optionalToken.isEmpty()) {
            throw new InvalidTokenException("Invalid Token Passed");
        }

        return optionalToken.get().getUser();
    }
}
