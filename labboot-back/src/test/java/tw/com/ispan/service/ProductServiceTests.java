package tw.com.ispan.service;

import java.util.List;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import tw.com.ispan.domain.ProductBean;

@SpringBootTest
public class ProductServiceTests {
    @Autowired
    private ProductService productService;

    @Test
    public void testSelect(){
        List<ProductBean> beans = productService.select(null);
		for(ProductBean bean : beans) {
			System.out.println("bean=" + bean);
		}
    }

	// @Test
	public void testCount() {
		JSONObject obj1 = new JSONObject()
				.put("rows", 3)
				.put("dir", false)
				.put("order", "id")
				.put("name", "a");
		long count1 = productService.count(obj1.toString());
		System.out.println("count1="+count1);

		JSONObject obj2 = new JSONObject()
				.put("id", "7");
		long count2 = productService.count(obj2.toString());
		System.out.println("count2="+count2);
	}
	
	// @Test
	public void testFind() {
		JSONObject obj1 = new JSONObject()
				.put("start", 3)      // 起始位置为3
				.put("rows", 3)       // 返回3条记录
				.put("dir", false)    // 排序方向为降序
				.put("order", "id")   // 按id字段排序
				.put("name", "a");    // 查询name为"a"的商品
		List<ProductBean> find1 = productService.find(obj1.toString());
		System.out.println("find1="+find1);

		JSONObject obj2 = new JSONObject()
				.put("id", "7");      // 查询id为"7"的商品
		List<ProductBean> find2 = productService.find(obj2.toString());
		System.out.println("find2="+find2);
	}

	// @Test
	public void testFindById() {
		ProductBean find = productService.findById(1);
		System.out.println("findById="+find);
	}

	// @Test
	public void testExists() {
		boolean exists = productService.exists(4);
		System.out.println("exists="+exists);
	}

	// @Test
	public void testCreate() {
		JSONObject obj = new JSONObject()
				.put("id", 100)
				.put("name", "hahaha")
				.put("price", 1.23)
				.put("make", "2025-03-11")
				.put("expire", 45);
		
		ProductBean create = productService.create(obj.toString());
		System.out.println("create="+create);
	}
	
	// @Test
	public void testModify() {
		JSONObject obj = new JSONObject()
				.put("id", 100)
				.put("name", "hohoho")
				.put("price", 6.78)
				.put("make", "2025-01-01")
				.put("expire", 90);
		
		ProductBean modify = productService.modify(obj.toString());
		System.out.println("modify="+modify);
	}

	// @Test
	public void testRemove() {
		boolean remove = productService.remove(100);
		System.out.println("remove="+remove);
	}

	// @Test
	public void testInsert() {
		ProductBean insert = new ProductBean();
		insert.setId(100);
		insert.setName("hahaha");
		insert.setPrice(1.23);
		insert.setMake(new java.util.Date());
		insert.setExpire(45);
		
		ProductBean result = productService.insert(insert);
		System.out.println("insert="+result);
	}

	// @Test
	public void testUpdate() {
		ProductBean update = new ProductBean();
		update.setId(100);
		update.setName("testtest");
		update.setPrice(98.76);
		update.setMake(new java.util.Date());
		update.setExpire(54);
		
		ProductBean result = productService.update(update);
		System.out.println("update="+result);
	}

	// @Test
	public void testDelete() {
		ProductBean delete = new ProductBean();
		delete.setId(100);
		
		boolean result = productService.delete(delete);
		System.out.println("delete="+result);
	}
}
