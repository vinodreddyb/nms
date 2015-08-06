package org.vinod.db.row;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;
import org.vinod.db.dao.dto.EntryDTO;

public class EntryRowMapper implements RowMapper<EntryDTO> {

	@Override
	public EntryDTO mapRow(ResultSet rs, int row) throws SQLException {
		
		EntryDTO entry = new EntryDTO();
		entry.setId(rs.getInt("id"));
		entry.setOrgname(rs.getString(EntryTable.orgname.name()));
		entry.setContactName(rs.getString(EntryTable.contactname.name()));
		entry.setEmail(rs.getString(EntryTable.email.name()));
		entry.setContactNum(rs.getString(EntryTable.contactnum.name()));
		entry.setLocation(rs.getString(EntryTable.location.name()));
		entry.setStartDate(rs.getDate(EntryTable.startdate.name()));
		entry.setEndDate(rs.getDate(EntryTable.enddate.name()));
		entry.setShutdownDate(rs.getDate(EntryTable.shutdowndate.name()));
		entry.setPrivateIp(rs.getString(EntryTable.privateip.name()));
		entry.setPublicIp(rs.getString(EntryTable.publicip.name()));
		entry.setService(rs.getString(EntryTable.service.name()));
		entry.setServiceType(rs.getString(EntryTable.servicetype.name()));
		entry.setPoNum(rs.getString(EntryTable.ponum.name()));
		entry.setPoDate(rs.getDate(EntryTable.podate.name()));
		entry.setManagerName(rs.getString(EntryTable.manager.name()));
		entry.setAccManager(rs.getInt(EntryTable.managerId.name()));
		entry.setVmName(rs.getString(EntryTable.vmname.name()));
		entry.setvRam(rs.getString(EntryTable.vmram.name()));
		entry.setvCpu(rs.getString(EntryTable.vcpu.name()));
		entry.setvHdd(rs.getString(EntryTable.vhdd.name()));
		entry.setOsVersion(rs.getString(EntryTable.osversion.name()));
		entry.setRemarks(rs.getString(EntryTable.remarks.name()));
		entry.setStatus(rs.getInt(EntryTable.status.name()));
		return entry;
	}

}
