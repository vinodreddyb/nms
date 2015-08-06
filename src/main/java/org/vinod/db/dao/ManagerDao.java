package org.vinod.db.dao;

import java.util.List;

import org.vinod.db.dao.dto.ManagerDTO;

public interface ManagerDao  {
	
	public void save(ManagerDTO managerDTO) throws Exception;
	public List<ManagerDTO> getAllManagers() throws Exception;
	public void update(final ManagerDTO managerDTO) throws Exception;
}
