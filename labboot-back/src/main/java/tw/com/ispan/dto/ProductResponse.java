package tw.com.ispan.dto;

import java.util.List;

import tw.com.ispan.domain.ProductBean;

public record ProductResponse(String message, Boolean success, Long count, List<ProductBean> list) {

}
