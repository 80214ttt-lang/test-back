package tw.com.ispan.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tw.com.ispan.domain.DetailBean;
import tw.com.ispan.repository.DetailRepository;

@Service
@Transactional
public class DetailService {
    @Autowired
    private DetailRepository detailRepository;

    public DetailBean select(Integer id) {
        if (id != null) {
            return detailRepository.findById(id).orElse(null);
        }
        return null;
    }
}
