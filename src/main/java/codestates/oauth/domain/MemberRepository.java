package codestates.oauth.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Member findByUsername(String username);
    boolean existsByEmail(String email);
}
