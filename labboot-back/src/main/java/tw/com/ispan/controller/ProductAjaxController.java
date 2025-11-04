package tw.com.ispan.controller;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import tw.com.ispan.domain.ProductBean;
import tw.com.ispan.dto.ProductResponse;
import tw.com.ispan.service.ProductService;
import tw.com.ispan.util.DatetimeConverter;

@RestController
@RequestMapping("/ajax/pages/products")
public class ProductAjaxController {
    @Autowired
    private ProductService productService;
    
    @PostMapping("/find")
    public ProductResponse find(@RequestBody String json) {
        long count = productService.count(json);
        List<ProductBean> products = productService.find(json);
        if(products!=null && !products.isEmpty()) {
            return new ProductResponse(null, null, count, products);
        } else {
            return new ProductResponse(null, null, count, new ArrayList<>());
        }
    }

    @GetMapping("/{id}")
    public String findById(@PathVariable Integer id) {
        JSONObject response = new JSONObject();
        JSONArray array = new JSONArray();
        if(id!=null) {
            ProductBean product = productService.findById(id);
            if(product!=null) {
                String make = DatetimeConverter.toString(product.getMake(), "yyyy-MM-dd");
                JSONObject item = new JSONObject()
                    .put("id", product.getId())
                    .put("name", product.getName())
                    .put("price", product.getPrice())
                    .put("make", make)
                    .put("expire", product.getExpire());
                array = array.put(item);
            }
        }
        response.put("list", array);
        return response.toString();
    }

    @DeleteMapping("/{id}")
    public ProductResponse remove(@PathVariable Integer id) {
        if(id==null) {
            return new ProductResponse("id是必要欄位", false, null, null);
        } else if(!productService.exists(id)) {
            return new ProductResponse("id不存在", false, null, null);
        } else {
            if(!productService.remove(id)) {
                return new ProductResponse("刪除失敗", false, null, null);
            } else {
                return new ProductResponse("刪除成功", true, null, null);
            }
        }
    }

    @PutMapping("/{id}")
    public ProductResponse modify(@PathVariable Integer id, @RequestBody String json) {
        if(id==null) {
            return new ProductResponse("id是必要欄位", false, null, null);
        } else if(!productService.exists(id)) {
            return new ProductResponse("id不存在", false, null, null);
        } else {
            ProductBean update = productService.modify(json);
            if(update==null) {
                return new ProductResponse("修改失敗", false, null, null);
            } else {
                return new ProductResponse("修改成功", true, null, null);
            }
        }
    }

    @PostMapping
    public ProductResponse create(@RequestBody String json) {
        JSONObject obj = new JSONObject(json);
        Integer id = obj.isNull("id") ? null : obj.getInt("id");
        if(id==null) {
            return new ProductResponse("id是必要欄位", false, null, null);
        } else if(productService.exists(id)) {
            return new ProductResponse("id已經存在", false, null, null);
        } else {
            ProductBean insert = productService.create(json);
            if(insert==null) {
                return new ProductResponse("新增失敗", false, null, null);
            } else {
                return new ProductResponse("新增成功", true, null, null);
            }
        }
    }
}
