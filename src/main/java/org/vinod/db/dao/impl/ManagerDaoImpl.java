package org.vinod.db.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.stereotype.Repository;
import org.vinod.db.dao.ManagerDao;
import org.vinod.db.dao.dto.ManagerDTO;

@Repository
public class ManagerDaoImpl implements ManagerDao {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	public void save(final ManagerDTO managerDTO) throws Exception {

		try {
			jdbcTemplate.update(new PreparedStatementCreator() {
				public PreparedStatement createPreparedStatement(Connection conn) throws SQLException {
					/*String trys = "INSERT INTO tbl_managers (name, mobile, email, location, isActive) VALUES (?, ?, ?, ?, ?)"
							+ "  ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)";*/
					String sql = "INSERT INTO tbl_managers(name, mobile, email, location, isActive) VALUES (?, ?, ?, ?, ?)";
					PreparedStatement ps = conn.prepareStatement(sql);
					ps.setString(1, managerDTO.getName());
					ps.setString(2, managerDTO.getMobile());
					ps.setString(3, managerDTO.getEmail());
					ps.setString(4, managerDTO.getLocation());
					ps.setInt(5, 1);
					return ps;
				}
			});
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} 
	}
	
	public void update(final ManagerDTO managerDTO) throws Exception {

		try {
			jdbcTemplate.update(new PreparedStatementCreator() {
				public PreparedStatement createPreparedStatement(Connection conn) throws SQLException {
					/*String trys = "INSERT INTO tbl_managers (name, mobile, email, location, isActive) VALUES (?, ?, ?, ?, ?)"
							+ "  ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)";*/
					String sql = "UPDATE tbl_managers set name = ?, mobile=?, email=?, location=? WHERE id= ?";
					PreparedStatement ps = conn.prepareStatement(sql);
					ps.setString(1, managerDTO.getName());
					ps.setString(2, managerDTO.getMobile());
					ps.setString(3, managerDTO.getEmail());
					ps.setString(4, managerDTO.getLocation());
					
					ps.setInt(5, managerDTO.getId());
					
					return ps;
				}
			});
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} 
	}
	
	public List<ManagerDTO> getAllManagers() throws Exception {
		List<ManagerDTO> managers = new ArrayList<>();
		try {
			String sql = "SELECT id, name, mobile, email, location from tbl_managers where isActive = 1";
			List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql);
			for (Map<String, Object> row : rows) {
				ManagerDTO manager = new ManagerDTO();
				manager.setId((Integer) row.get("id"));
				manager.setName((String) row.get("name"));
				manager.setEmail((String) row.get("email"));
				manager.setMobile((String) row.get("mobile"));
				manager.setLocation((String) row.get("location"));
				managers.add(manager);
			}
		} catch (Exception e) {
			throw e;
		}
		
		return managers;
	}
}
