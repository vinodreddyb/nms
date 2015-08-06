package org.vinod.jsf.service;

import java.util.List;

import org.vinod.jsf.bean.vo.Manager;

public interface ManagerService {
	public void save(Manager manager) throws Exception ;
	public List<Manager> getAllManagers() throws Exception ;
	public void update(Manager manager) throws Exception ;
}
