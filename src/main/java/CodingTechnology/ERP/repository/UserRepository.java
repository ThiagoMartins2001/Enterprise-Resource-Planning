package CodingTechnology.ERP.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import CodingTechnology.ERP.model.User;
import jakarta.transaction.Transactional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);;
    boolean existsByUsername(String username);
    
    @Transactional
    void deleteByUsername(String username);
}
