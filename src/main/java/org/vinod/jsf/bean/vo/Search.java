package org.vinod.jsf.bean.vo;

import java.io.Serializable;

public class Search implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = -4322080318199706415L;
	private String searchValue;
	private String searchBy ="customer";
	private String searchService;
	private int status;
	public String getSearchValue() {
		return searchValue;
	}
	public void setSearchValue(String searchValue) {
		this.searchValue = searchValue;
	}
	public String getSearchBy() {
		return searchBy;
	}
	public void setSearchBy(String searchBy) {
		this.searchBy = searchBy;
	}
	public String getSearchService() {
		return searchService;
	}
	public void setSearchService(String searchService) {
		this.searchService = searchService;
	}
	public int getStatus() {
		return status;
	}
	public void setStatus(int status) {
		this.status = status;
	}
	
	
}
