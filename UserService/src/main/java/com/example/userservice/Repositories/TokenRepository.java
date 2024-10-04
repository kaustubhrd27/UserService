package com.example.userservice.Repositories;

import com.example.userservice.Models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    @Override
    Token save(Token token);

    //select * from tokens where value = <> and is_deleted = false
    Optional<Token> findByValueAndIsDeleted(String value, boolean isDeleted);
}
