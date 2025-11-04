package tw.com.ispan.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import tw.com.ispan.domain.DetailBean;

@Repository
public interface DetailRepository extends JpaRepository<DetailBean, Integer> {

}
