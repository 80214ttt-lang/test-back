package tw.com.ispan.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "product")
@Data
public class ProductBean {
	@Id
	@Column(name = "id")
	private Integer id;

	@Column(name = "name")
	private String name;

	@Column(name = "price")
	private Double price;

	@Column(name = "make")
	private java.util.Date make;

	@Column(name = "expire")
	private Integer expire;

	@JsonIgnoreProperties("product")
	// @JsonManagedReference("product")
	// @JsonBackReference("product")
	@OneToOne(mappedBy = "product", cascade = CascadeType.ALL)
	private DetailBean detail;

	@Override
	public String toString() {
		return "ProductBean [id=" + id + ", name=" + name + ", price=" + price + ", make=" + make + ", expire=" + expire+ "]";
	}
}
