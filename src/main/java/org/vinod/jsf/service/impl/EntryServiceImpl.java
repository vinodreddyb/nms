package org.vinod.jsf.service.impl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.vinod.db.dao.EntryDao;
import org.vinod.db.dao.dto.EntryDTO;
import org.vinod.jsf.bean.vo.Entry;
import org.vinod.jsf.bean.vo.Search;
import org.vinod.jsf.service.EntryService;

@Service
public class EntryServiceImpl implements EntryService {
	
	@Autowired
	private EntryDao entryDao;

	/**
	 * This method saves the entry into database
	 * @param {@link Entry}
	 */
	public void save(Entry entry) throws Exception {
		EntryDTO entryDTO = entryVoToDto(entry);
		try {
			entryDao.saveEntry(entryDTO);
		} catch (Exception e) {
			throw e;
		}
	}

	/**
	 * This method edit the existing entry 
	 * @param {@link Entry}
	 */
	public void edit(Entry entry) throws Exception {
		EntryDTO entryDTO = entryVoToDto(entry);
		try {
			entryDTO.setId(entry.getId());
			entryDao.updateEntry(entryDTO);
		} catch (Exception e) {
			throw e;
		}
	}
	
	/**
	 * This method edit the existing entry 
	 * @param {@link Search}
	 */
	public List<Entry> searchEntry(Search search) throws Exception {
		List<Entry> entries = new ArrayList<>();
		try {
			List<EntryDTO> result = entryDao.searchEntry(search);
			for(EntryDTO entryDTO : result) {
				Entry entry = entryDtoToVo(entryDTO);
				entries.add(entry);
			}
		} catch (Exception e) {
			throw e;
		}
		return entries;
	}

	private Entry entryDtoToVo(EntryDTO entryDTO) {
		Entry entry = new Entry();
		entry.setId(entryDTO.getId());
		entry.setOrgname(entryDTO.getOrgname());
		entry.setContactName(entryDTO.getContactName());
		entry.setEmail(entryDTO.getEmail());
		entry.setContactNum(entryDTO.getContactNum());
		entry.setLocation(entryDTO.getLocation());
		entry.setStartDate(new Date(entryDTO.getStartDate().getTime()));
		if(entryDTO.getEndDate() != null) {
			entry.setEndDate(new Date(entryDTO.getEndDate().getTime()));
		}
		if(entryDTO.getShutdownDate() != null) {
		  entry.setShutdownDate(new Date(entryDTO.getShutdownDate().getTime()));
		}
		entry.setPrivateIp(entryDTO.getPrivateIp());
		entry.setPublicIp(entryDTO.getPublicIp());
		entry.setService(entryDTO.getService());
		entry.setServiceType(entryDTO.getServiceType());
		entry.setPoNum(entryDTO.getPoNum());
		if(entryDTO.getPoDate() != null) {
		 entry.setPoDate(new Date(entryDTO.getPoDate().getTime()));
		}
		entry.setManagerName(entryDTO.getManagerName());
		entry.setAccManager(entryDTO.getAccManager());
		entry.setVmName(entryDTO.getVmName());
		entry.setvRam(entryDTO.getvRam());
		entry.setvCpu(entryDTO.getvCpu());
		entry.setvHdd(entryDTO.getvHdd());
		entry.setOsVersion(entryDTO.getOsVersion());
		entry.setRemarks(entryDTO.getRemarks());
		entry.setStatus(entryDTO.getStatus());
		return entry;
	}
	
	private EntryDTO entryVoToDto(Entry entry) {
		EntryDTO entryDTO = new EntryDTO();
		entryDTO.setOrgname(entry.getOrgname());
		entryDTO.setContactName(entry.getContactName());
		entryDTO.setEmail(entry.getEmail());
		entryDTO.setContactNum(entry.getContactName());
		entryDTO.setLocation(entry.getLocation());
		entryDTO.setStartDate(new java.sql.Date(entry.getStartDate().getTime()));
		if(entry.getEndDate() !=null) {
			entryDTO.setEndDate(new java.sql.Date(entry.getEndDate().getTime()));
		}
		if(entry.getShutdownDate() != null){
			entryDTO.setShutdownDate(new java.sql.Date(entry.getShutdownDate().getTime()));
		}
		
		entryDTO.setPrivateIp(entry.getPrivateIp());
		entryDTO.setPublicIp(entry.getPublicIp());
		entryDTO.setService(entry.getService());
		entryDTO.setServiceType(entry.getServiceType());
		if(entry.getServiceType().equals("PAID")) {
			entryDTO.setPoNum(entry.getPoNum());
			entryDTO.setPoDate(new java.sql.Date(entry.getPoDate().getTime()));
		}
		
		entryDTO.setAccManager(entry.getAccManager());
		entryDTO.setVmName(entry.getVmName());
		entryDTO.setvRam(entry.getvRam());
		entryDTO.setvCpu(entry.getvCpu());
		entryDTO.setvHdd(entry.getvHdd());
		entryDTO.setOsVersion(entry.getOsVersion());
		entryDTO.setStatus(entry.getStatus());;
		entryDTO.setRemarks(entry.getRemarks());
		return entryDTO;
	}
}
