package tw.com.ispan.repository;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.Session;
import org.json.JSONObject;
import org.springframework.stereotype.Repository;

import jakarta.persistence.PersistenceContext;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import tw.com.ispan.domain.ProductBean;
import tw.com.ispan.util.DatetimeConverter;

@Repository
public class ProductDAOImpl implements ProductDAO {
	@PersistenceContext
	private Session session;

	public Session getSession() {
		return session;
	}

	@Override
	public List<ProductBean> find(JSONObject obj) {
		Integer id = obj.isNull("id") ? null : obj.getInt("id");
		String name = obj.isNull("name") ? null : obj.getString("name");
		Double minPrice = obj.isNull("minPrice") ? null : obj.getDouble("minPrice");
		Double maxPrice = obj.isNull("maxPrice") ? null : obj.getDouble("maxPrice");
		String minMake = obj.isNull("minMake") ? null : obj.getString("minMake");
		String maxMake = obj.isNull("maxMake") ? null : obj.getString("maxMake");
		Integer minExpire = obj.isNull("minExpire") ? null : obj.getInt("minExpire");
		Integer maxExpire = obj.isNull("maxExpire") ? null : obj.getInt("maxExpire");

		int start = obj.isNull("start") ? 0 : obj.getInt("start");
		int rows = obj.isNull("rows") ? 5 : obj.getInt("rows");
		boolean dir = obj.isNull("dir") ? false : obj.getBoolean("dir");
		String order = obj.isNull("order") ? "id" : obj.getString("order");

		CriteriaBuilder criteriaBuilder = this.getSession().getCriteriaBuilder();
		CriteriaQuery<ProductBean> criteriaQuery = criteriaBuilder.createQuery(ProductBean.class);

		// from
		Root<ProductBean> table = criteriaQuery.from(ProductBean.class);

		// where
		List<Predicate> predicates = new ArrayList<>();
		if (id != null) {
			predicates.add(criteriaBuilder.equal(table.get("id"), id));
		}
		if (name != null && name.length() != 0) {
			// Predicate p = criteriaBuilder.like(table.get("name"), "%"+name+"%");
			// predicates.add(p);
			predicates.add(criteriaBuilder.like(table.get("name"), "%" + name + "%"));
		}
		if (minPrice != null) {
			predicates.add(criteriaBuilder.greaterThan(table.get("price"), minPrice));
		}
		if (maxPrice != null) {
			predicates.add(criteriaBuilder.lessThan(table.get("price"), maxPrice));
		}
		if (minMake != null && minMake.length() != 0) {
			java.util.Date make = DatetimeConverter.parse(minMake, "yyyy-MM-dd");
			predicates.add(criteriaBuilder.greaterThan(table.get("make"), make));
		}
		if (maxMake != null && maxMake.length() != 0) {
			java.util.Date make = DatetimeConverter.parse(maxMake, "yyyy-MM-dd");
			predicates.add(criteriaBuilder.lessThan(table.get("make"), make));
		}
		if (minExpire != null) {
			predicates.add(criteriaBuilder.greaterThanOrEqualTo(table.get("expire"),
					minExpire));
		}
		if (maxExpire != null) {
			predicates.add(criteriaBuilder.lessThanOrEqualTo(table.get("expire"),
					maxExpire));
		}

		if (!predicates.isEmpty()) {
			// criteriaQuery = criteriaQuery.where(predicates);
			Predicate[] array = predicates.toArray(new Predicate[1]);
			criteriaQuery = criteriaQuery.where(array);
		}

		// order by
		if (dir) {
			Order o = criteriaBuilder.desc(table.get(order));
			criteriaQuery = criteriaQuery.orderBy(o);
		} else {
			criteriaQuery = criteriaQuery.orderBy(
					criteriaBuilder.asc(table.get(order)));
		}

		// TypedQuery<ProductBean> typedQuery =
		// this.getSession().createQuery(criteriaQuery);
		// typedQuery = typedQuery.setFirstResult(start);
		// typedQuery = typedQuery.setMaxResults(rows);
		// List<ProductBean> result = typedQuery.getResultList();

		List<ProductBean> result = this.getSession().createQuery(criteriaQuery)
				.setFirstResult(start)
				.setMaxResults(rows)
				.getResultList();
		if (result != null && !result.isEmpty()) {
			return result;
		} else {
			return null;
		}
	}

	@Override
	public long count(JSONObject obj) {
		Integer id = obj.isNull("id") ? null : obj.getInt("id");
		String name = obj.isNull("name") ? null : obj.getString("name");
		Double minPrice = obj.isNull("minPrice") ? null : obj.getDouble("minPrice");
		Double maxPrice = obj.isNull("maxPrice") ? null : obj.getDouble("maxPrice");
		String minMake = obj.isNull("minMake") ? null : obj.getString("minMake");
		String maxMake = obj.isNull("maxMake") ? null : obj.getString("maxMake");
		Integer minExpire = obj.isNull("minExpire") ? null : obj.getInt("minExpire");
		Integer maxExpire = obj.isNull("maxExpire") ? null : obj.getInt("maxExpire");

		CriteriaBuilder criteriaBuilder = this.getSession().getCriteriaBuilder();
		CriteriaQuery<Long> criteriaQuery = criteriaBuilder.createQuery(Long.class);

		// from product
		Root<ProductBean> table = criteriaQuery.from(ProductBean.class);

		// where
		List<Predicate> predicates = new ArrayList<>();
		if (id != null) {
			predicates.add(criteriaBuilder.equal(table.get("id"), id));
		}
		if (name != null && name.length() != 0) {
			// Predicate p = criteriaBuilder.like(table.get("name"), "%"+name+"%");
			// predicates.add(p);
			predicates.add(criteriaBuilder.like(table.get("name"), "%" + name + "%"));
		}
		if (minPrice != null) {
			predicates.add(criteriaBuilder.greaterThan(table.get("price"), minPrice));
		}
		if (maxPrice != null) {
			predicates.add(criteriaBuilder.lessThan(table.get("price"), maxPrice));
		}
		if (minMake != null && minMake.length() != 0) {
			java.util.Date make = DatetimeConverter.parse(minMake, "yyyy-MM-dd");
			predicates.add(criteriaBuilder.greaterThan(table.get("make"), make));
		}
		if (maxMake != null && maxMake.length() != 0) {
			java.util.Date make = DatetimeConverter.parse(maxMake, "yyyy-MM-dd");
			predicates.add(criteriaBuilder.lessThan(table.get("make"), make));
		}
		if (minExpire != null) {
			predicates.add(criteriaBuilder.greaterThanOrEqualTo(table.get("expire"),
					minExpire));
		}
		if (maxExpire != null) {
			predicates.add(criteriaBuilder.lessThanOrEqualTo(table.get("expire"),
					maxExpire));
		}

		if (!predicates.isEmpty()) {
			// criteriaQuery = criteriaQuery.where(predicates);
			Predicate[] array = predicates.toArray(new Predicate[1]);
			criteriaQuery = criteriaQuery.where(array);
		}

		// select count(*)
		Expression<Long> exp = criteriaBuilder.count(table);
		criteriaQuery = criteriaQuery.select(exp);

		TypedQuery<Long> typedQuery = this.getSession().createQuery(criteriaQuery);
		Long result = typedQuery.getSingleResult();
		if (result != null) {
			return result.longValue();
		} else {
			return 0;
		}
	}
}
