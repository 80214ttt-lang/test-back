package tw.com.ispan.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tw.com.ispan.domain.ProductBean;
import tw.com.ispan.repository.ProductRepository;
import tw.com.ispan.util.DatetimeConverter;

@Service
@Transactional
public class ProductService {
    @Autowired
    private ProductRepository productRepository;

	public ProductBean findById(Integer id) {
		if(id!=null) {
			Optional<ProductBean> optional = productRepository.findById(id);
			if(optional!=null && optional.isPresent()) {
				return optional.get();
			}
		}
		return null;
	}

	public boolean exists(Integer id) {
		if(id!=null) {
			return productRepository.existsById(id);
		}
		return false;
	}

	public ProductBean create(String json) {
		try {
			JSONObject obj = new JSONObject(json);
			Integer id = obj.isNull("id") ? null : obj.getInt("id");
			String name = obj.isNull("name") ? null : obj.getString("name");
			Double price = obj.isNull("price") ? null : obj.getDouble("price");
			String make = obj.isNull("make") ? null : obj.getString("make");
			Integer expire = obj.isNull("expire") ? null : obj.getInt("expire");		
			if(id!=null) {
				Optional<ProductBean> optional = this.productRepository.findById(id);
				if(optional!=null && optional.isEmpty()) {
					ProductBean insert = new ProductBean();
					insert.setId(id);
					insert.setName(name);
					insert.setPrice(price);
					if(make!=null && make.length()!=0) {
						insert.setMake(DatetimeConverter.parse(make, "yyyy-MM-dd"));
					} else {
						insert.setMake(null);
					}
					insert.setExpire(expire);
					return this.productRepository.save(insert);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public ProductBean modify(String json) {
		try {
			JSONObject obj = new JSONObject(json);
			Integer id = obj.isNull("id") ? null : obj.getInt("id");
			String name = obj.isNull("name") ? null : obj.getString("name");
			Double price = obj.isNull("price") ? null : obj.getDouble("price");
			String make = obj.isNull("make") ? null : obj.getString("make");
			Integer expire = obj.isNull("expire") ? null : obj.getInt("expire");

			if(id!=null) {
				Optional<ProductBean> optional = productRepository.findById(id);
				if(optional!=null && optional.isPresent()) {
					ProductBean update = optional.get();
					update.setName(name);
					update.setPrice(price);
					if(make!=null && make.length()!=0) {
						update.setMake(DatetimeConverter.parse(make, "yyyy-MM-dd"));
					} else {
						update.setMake(null);
					}
					update.setExpire(expire);
					
					return this.productRepository.save(update);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public boolean remove(Integer id) {
		if(id!=null) {
			try {
				Optional<ProductBean> optional = this.productRepository.findById(id);
				if(optional!=null && optional.isPresent()) {
					this.productRepository.deleteById(id);
					return true;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}	
		}
		return false;
	}

    public List<ProductBean> find(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            return productRepository.find(obj);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return null;
    }
    public long count(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            return productRepository.count(obj);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return 0;
    }

    public List<ProductBean> select(ProductBean bean) {
        List<ProductBean> result = null;
        if (bean != null && bean.getId() != null && !bean.getId().equals(0)) {
            Optional<ProductBean> optional = productRepository.findById(bean.getId());
            if(optional.isPresent()) {
                ProductBean temp = optional.get();
                result = new ArrayList<ProductBean>();
                result.add(temp);
            }
        } else {
            result = productRepository.findAll();
        }
        return result;
    }

    public ProductBean insert(ProductBean bean) {
        ProductBean result = null;
        if (bean != null && bean.getId() != null) {
            if(!productRepository.existsById(bean.getId())) {
                result = productRepository.save(bean);
            }
        }
        return result;
    }

    public ProductBean update(ProductBean bean) {
        ProductBean result = null;
        if (bean != null && bean.getId() != null) {
            if(productRepository.existsById(bean.getId())) {
                result = productRepository.save(bean);
            }
        }
        return result;
    }

    public boolean delete(ProductBean bean) {
        if (bean != null && bean.getId() != null) {
            if(productRepository.existsById(bean.getId())) {
                productRepository.deleteById(bean.getId());
                return true;
            }
        }
        return false;
    }
}
