package org.vinod.db.dao;

import java.util.List;

import org.vinod.db.dao.dto.EntryDTO;
import org.vinod.jsf.bean.vo.Search;

public interface EntryDao {
	public void saveEntry(final EntryDTO entry) throws Exception;
	public List<EntryDTO> searchEntry(Search search) throws Exception;
	public void updateEntry(final EntryDTO entry) throws Exception;
}
