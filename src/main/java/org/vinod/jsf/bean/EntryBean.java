package org.vinod.jsf.bean;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.event.RowEditEvent;
import org.primefaces.event.TabChangeEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.vinod.jsf.bean.vo.Entry;
import org.vinod.jsf.bean.vo.Manager;
import org.vinod.jsf.bean.vo.Search;
import org.vinod.jsf.service.EntryService;
import org.vinod.jsf.service.ManagerService;

/**
 * 
 * @author vinod
 *
 */
@Component
@ManagedBean
@ViewScoped
public class EntryBean {
	private Logger log = Logger.getLogger(EntryBean.class);
	@Autowired
	private ManagerService managerService;
	
	@Autowired
	private EntryService entryService;

	private List<Manager> listManagers = null;
	
	private List<Entry> listEntries = new ArrayList<>();
	
	private Entry entry = new Entry();
	
	private Search search = new Search();
	
	/**
	 * 
	 */
	public void save() {
		FacesContext context = FacesContext.getCurrentInstance();
		try {
			boolean isDataValid = validate(entry, context);
			if(!isDataValid) {
				return;
			}
			entryService.save(entry);
			setEntry(new Entry());
	        context.addMessage(null, new FacesMessage("",  "Entry saved Succcessfully") );
	   } catch (Exception e) {
		   log.error("Exception while saving Entry" + e.toString());
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Exception while saving Entry", 
					e.getLocalizedMessage()));
			//setEntry(new Entry());
		} 
	}
	
	/**
	 * 
	 */
	public void reset() {
		setEntry(new Entry());
	}
	/**
	 * 
	 */
	
	public void resetSearch() {
		setSearch(new Search());
	}
	/**
	 * This method do the search
	 */
	public void search() {
		FacesContext context = FacesContext.getCurrentInstance();
		try {
			
			setListEntries(entryService.searchEntry(search));
	        
	   } catch (Exception e) {
		   log.error("Exception while searching Entry" + e.toString());
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Exception occured while search Entries", 
					e.getLocalizedMessage()));
			 
			e.printStackTrace();
		} finally {
			setSearch(new Search());
		}
	}
	
	public void onTabChange(TabChangeEvent event) {
		
		String tabClicked = event.getTab().getTitle();
		if("Search".equalsIgnoreCase(tabClicked)) {
			setSearch(new Search());
			setListEntries(new ArrayList<Entry>());
		} else if("Data".equalsIgnoreCase(tabClicked)) {
			loadAllManagers();
		}
        
    }
	
	public void loadAllManagers() {
		try {
			listManagers = managerService.getAllManagers();
		} catch (Exception e) {
			log.error("Exception while loading managers " + e.toString());
		}
	}
	
	public void onRowEdit(RowEditEvent event) {
		FacesContext context = FacesContext.getCurrentInstance();
		Entry editedEntry = (Entry) event.getObject();
		
		try {
			boolean isDataValid = validate(editedEntry, context);
			if(!isDataValid) {
				return;
			}
			entryService.edit(editedEntry);
			Optional<Manager> m = listManagers.stream().filter(user -> user.getId() == editedEntry.getAccManager()).findFirst();
			if(m.isPresent()) {
				editedEntry.setManagerName(m.get().getName());
			}
			
		} catch (Exception e) {
			log.error("Exception while editing Entry" + e.toString());
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Exception occured editing Entry " + editedEntry.getId(), 
					e.toString()));
		}
	}
	private boolean validate(Entry entry, FacesContext context) {
		
		if("".equals(entry.getService())) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Validation Error", 
					"Please select Service"));
			return false;
		}
		if(entry.getAccManager() == 0) {
			context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Validation Error", 
					"Please select Manager"));
			return false;
		}
		
		Date sd = entry.getStartDate();
		Date ed = entry.getEndDate();
		Date shutDate = entry.getShutdownDate();
		
		
		if("POC".equals(entry.getServiceType())) {
			/*if(ed == null) {
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Validation Error", 
						"Please enter End date for POC service"));
				return false;
			}
			if(!sd.before(ed)) {
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Validation Error", 
						"End date should be after start date"));
				return false;
			}
			if(shutDate != null && !shutDate.after(ed)) {
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Validation Error", 
						"Shutdown date should be after end date"));
				return false;
			}*/
			
			
		} else if("PAID".equals(entry.getServiceType())) {
			/*if(entry.getPoNum() == null || "".equals(entry.getPoNum())) {
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Validation Error", 
						"Please enter PO number for PAID service"));
				return false;
			}*/
			if(entry.getPoDate() == null) {
				context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Validation Error", 
						"Please enter PO date for PAID service"));
				return false;
			}
		}
		
		return true;
		
		
	}

	public List<Manager> getListManagers() {
		return listManagers;
	}

	public void setListManagers(List<Manager> listManagers) {
		this.listManagers = listManagers;
	}

	public Entry getEntry() {
		return entry;
	}

	public void setEntry(Entry entry) {
		this.entry = entry;
	}

	public List<Entry> getListEntries() {
		return listEntries;
	}

	public void setListEntries(List<Entry> listEntries) {
		this.listEntries = listEntries;
	}

	public Search getSearch() {
		return search;
	}

	public void setSearch(Search search) {
		this.search = search;
	}
}