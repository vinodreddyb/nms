package org.vinod.jsf.bean;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;

import org.primefaces.event.SelectEvent;
import org.primefaces.event.ToggleEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.vinod.jsf.bean.vo.Manager;
import org.vinod.jsf.service.ManagerService;

@Component
@ManagedBean
@ViewScoped
public class ManagerBean implements Serializable {

	private Manager manager = new Manager();
	
	private List<Manager> listManagers = new ArrayList<>();
	
	private boolean displayManagers;
	
	private boolean isUpdateRequest;
	
	@Autowired
	private ManagerService managerService;
	
	public void saveManager() {
		FacesContext context = FacesContext.getCurrentInstance();
		String message = "";
		try {
			if(isUpdateRequest) {
				message = "Manager Update Successfully";
				managerService.update(manager);
				setUpdateRequest(false);
			} else {
				message = "Manager Added Successfully";
				managerService.save(manager);
			}
			
			manager = new Manager();
			setDisplayManagers(false);
			
	        context.addMessage(null, new FacesMessage("Successful",  message) );
	        
		} catch (Exception e) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Exception while saving/updating manager", 
					e.toString()));
			e.printStackTrace();
		}
	}
	
	/*public void update() {
		FacesContext context = FacesContext.getCurrentInstance();
		try {
			managerService.save(manager);
			manager = new Manager();
			setDisplayManagers(false);
	        context.addMessage(null, new FacesMessage("Successful",  "Manager Added Successfully") );
		} catch (Exception e) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Exception while saving manager", 
					e.toString()));
			e.printStackTrace();
		}
	}*/
	
	public void onToggle(ToggleEvent event) {
		
		if("VISIBLE".equalsIgnoreCase(event.getVisibility().name())) {
			loadAllActiveManagers();
		}
       
    }
	
	public void onRowSelect(SelectEvent event) {
		Manager manager = (Manager) event.getObject();
	    setManager(manager);
	    setUpdateRequest(true);
    }
	
	private void loadAllActiveManagers() {
		FacesContext context = FacesContext.getCurrentInstance();
		try {
			setListManagers(managerService.getAllManagers());
			setDisplayManagers(true);
		} catch (Exception e) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Exception while saving manager", 
					e.toString()));
		}
	}

	public Manager getManager() {
		return manager;
	}

	public void setManager(Manager manager) {
		this.manager = manager;
	}

	public List<Manager> getListManagers() {
		return listManagers;
	}

	public void setListManagers(List<Manager> listManagers) {
		this.listManagers = listManagers;
	}

	public boolean isDisplayManagers() {
		return displayManagers;
	}

	public void setDisplayManagers(boolean displayManagers) {
		this.displayManagers = displayManagers;
	}

	public boolean isUpdateRequest() {
		return isUpdateRequest;
	}

	public void setUpdateRequest(boolean isUpdateRequest) {
		this.isUpdateRequest = isUpdateRequest;
	}
	
}
