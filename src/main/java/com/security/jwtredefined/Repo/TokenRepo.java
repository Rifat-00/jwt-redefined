package com.security.jwtredefined.Repo;

import com.security.jwtredefined.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepo extends JpaRepository<Token,Integer> {

    @Query("""
   select t from Token t inner join User u on t.user.id = u.id
   where u.id=:id and (t.isExpired=false or t.isRevoked=false)
""")
    List<Token> findAllValidTokenByUserId(Integer id);

    Optional<Token> findByToken(String token);


}
