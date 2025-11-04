//package tw.com.ispan.service;
//
//import java.io.FileOutputStream;
//
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import tw.com.ispan.domain.DetailBean;
//
//@SpringBootTest
//public class DetailServiceTests {
//    @Autowired
//    private DetailService detailService;
//    
//	@Test
//	public void testFindById() throws Exception {
//		DetailBean detail = detailService.select(2);
//		System.out.println("detail="+detail);
//		if(detail!=null) {
//			byte[] photo = detail.getPhoto();
//			if(photo!=null && photo.length!=0) {
//				FileOutputStream out = new FileOutputStream("C:/Users/User/Desktop/demo.jpg");
//				out.write(photo, 0, photo.length);
//				out.close();
//			}
//		}
//	}
//}
