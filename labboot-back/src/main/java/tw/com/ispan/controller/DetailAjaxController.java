package tw.com.ispan.controller;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.PostConstruct;
import tw.com.ispan.domain.DetailBean;
import tw.com.ispan.service.DetailService;

@RestController
public class DetailAjaxController {
    @Autowired
    private DetailService detailService;

    @GetMapping(
		path = "/pages/detail/{photoid}",
		produces = {MediaType.IMAGE_JPEG_VALUE}
	)
    public @ResponseBody byte[] findPhotoByPhotoId(@PathVariable(name = "photoid") Integer photoid) {
        byte[] result = null;
        DetailBean detail = detailService.select(photoid);
        if(detail!=null) {
            result = detail.getPhoto();
        }
        if(result==null || result.length==0) {
            result = this.photo;
        }
        return result;
    }

    private byte[] photo = null;
    @PostConstruct
    public void initialize() throws IOException {
		byte[] buffer = new byte[8192];

		ClassLoader classLoader = getClass().getClassLoader();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		BufferedInputStream is = new BufferedInputStream(
            classLoader.getResourceAsStream("static/images/no-image.jpg"));
		int len = is.read(buffer);
		while(len!=-1) {
			os.write(buffer, 0, len);
			len = is.read(buffer);
		}
		is.close();
		this.photo = os.toByteArray();
    }
}
