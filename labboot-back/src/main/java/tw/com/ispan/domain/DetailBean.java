package tw.com.ispan.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Table(name = "detail")
@Data
public class DetailBean {
	@Id
	@Column(name = "photoid")
	private Integer photoid;

	@JsonIgnore
	@Column(name = "photo")
	private byte[] photo;

	@JsonIgnoreProperties("detail")
	// @JsonBackReference("detail")
	// @JsonManagedReference("detail")
	@OneToOne
	@JoinColumn(name = "photoid", referencedColumnName = "id")
	private ProductBean product;

	@Override
	public String toString() {
		return "DetailBean [photoid=" + photoid + "]";
	}
}
