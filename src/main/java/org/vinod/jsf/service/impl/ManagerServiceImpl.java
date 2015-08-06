package org.vinod.jsf.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.vinod.db.dao.ManagerDao;
import org.vinod.db.dao.dto.ManagerDTO;
import org.vinod.jsf.bean.vo.Manager;
import org.vinod.jsf.service.ManagerService;

@Service
public class ManagerServiceImpl implements ManagerService {
 
	@Autowired
	private ManagerDao managerDao;
	
	public void save(Manager manager) throws Exception {
		ManagerDTO dto = new ManagerDTO();
		dto.setName(manager.getName());
		dto.setMobile(manager.getMobile());
		dto.setEmail(manager.getEmail());
		dto.setLocation(manager.getLocation());
		managerDao.save(dto);
	}
	
	public void update(Manager manager) throws Exception {
		ManagerDTO dto = new ManagerDTO();
		dto.setId(manager.getId());
		dto.setName(manager.getName());
		dto.setMobile(manager.getMobile());
		dto.setEmail(manager.getEmail());
		dto.setLocation(manager.getLocation());
		managerDao.update(dto);
	}
	
	public List<Manager> getAllManagers() throws Exception {
		List<Manager> managers = new ArrayList<>();
		List<ManagerDTO> managersFrmDB = managerDao.getAllManagers();
		for(ManagerDTO managerDB : managersFrmDB) {
			Manager manager = new Manager();
			manager.setId(managerDB.getId());
			manager.setName(managerDB.getName());
			manager.setEmail(managerDB.getEmail());
			manager.setMobile(managerDB.getMobile());
			manager.setLocation(managerDB.getLocation());
			managers.add(manager);
		}
		
		return managers;
		
	}
}
