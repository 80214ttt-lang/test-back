package tw.com.ispan.service;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import tw.com.ispan.domain.CustomerBean;
import tw.com.ispan.repository.CustomerRepository;

@Service
public class CustomerService {
	@Autowired
	private CustomerRepository customerRepository;
	public CustomerBean login(String username, String password) {
		if (username != null && username.length() != 0 && password != null &&
				password.length() != 0) {
			Optional<CustomerBean> optional = customerRepository.findById(username);
			if (optional.isPresent()) {
				CustomerBean customer = optional.get();
				byte[] pass = customer.getPassword(); // 資料庫抓出
				byte[] temp = password.getBytes(); // 使用者輸入
				if (Arrays.equals(pass, temp)) {
					return customer;
				}
			}
		}
		return null;
	}

	public boolean changePassword(String username, String oldPass, String newPass) {
		CustomerBean customer = this.login(username, oldPass);
		if (customer != null) {
			if (newPass != null && newPass.length() != 0) {
				byte[] pass = newPass.getBytes();
				customer.setPassword(pass);
				CustomerBean result = customerRepository.save(customer);
				if (result != null) {
					return true;
				}
			}
		}
		return false;
	}
}
