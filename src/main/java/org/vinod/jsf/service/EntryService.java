package org.vinod.jsf.service;

import java.util.List;

import org.vinod.jsf.bean.vo.Entry;
import org.vinod.jsf.bean.vo.Search;

public interface EntryService {
	public void save(Entry entry) throws Exception ;
	public void edit(Entry entry) throws Exception ;
	public List<Entry> searchEntry(Search search) throws Exception;
	
}
