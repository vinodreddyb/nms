package org.vinod.jsf.bean.vo;

import java.io.Serializable;
import java.util.Date;

public class Entry implements Serializable{

	
	private static final long serialVersionUID = -4922075010535500508L;

	private String payService = "POC";
	
	private int id;
	private String orgname;
	private String contactName;
	private String email;
	private String contactNum;
	private String location;
	private Date startDate;
	private Date endDate;
	private Date shutdownDate;
	private String privateIp;
	private String publicIp;
	private String service;
	private String serviceType = "POC";
	private String poNum;
	private Date poDate;
	private int accManager;
	private String vmName;
	private String vRam;
	private String vCpu;
	private String vHdd;
	private String osVersion;
	private String remarks;
	private Date entryDate;
	private int status;
	
	private String managerName;

	
	public String getOrgname() {
		return orgname;
	}

	public void setOrgname(String orgname) {
		this.orgname = orgname;
	}

	public String getContactName() {
		return contactName;
	}

	public void setContactName(String contactName) {
		this.contactName = contactName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getContactNum() {
		return contactNum;
	}

	public void setContactNum(String contactNum) {
		this.contactNum = contactNum;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	

	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

	public Date getShutdownDate() {
		return shutdownDate;
	}

	public void setShutdownDate(Date shutdownDate) {
		this.shutdownDate = shutdownDate;
	}

	public Date getEntryDate() {
		return entryDate;
	}

	public void setEntryDate(Date entryDate) {
		this.entryDate = entryDate;
	}

	public String getPrivateIp() {
		return privateIp;
	}

	public void setPrivateIp(String privateIp) {
		this.privateIp = privateIp;
	}

	public String getPublicIp() {
		return publicIp;
	}

	public void setPublicIp(String publicIp) {
		this.publicIp = publicIp;
	}

	public String getService() {
		return service;
	}

	public void setService(String service) {
		this.service = service;
	}

	public String getServiceType() {
		return serviceType;
	}

	public void setServiceType(String serviceType) {
		this.serviceType = serviceType;
	}

	public String getPoNum() {
		return poNum;
	}

	public void setPoNum(String poNum) {
		this.poNum = poNum;
	}

	public Date getPoDate() {
		return poDate;
	}

	public void setPoDate(Date poDate) {
		this.poDate = poDate;
	}

	public int getAccManager() {
		return accManager;
	}

	public void setAccManager(int accManager) {
		this.accManager = accManager;
	}

	public String getVmName() {
		return vmName;
	}

	public void setVmName(String vmName) {
		this.vmName = vmName;
	}

	public String getvRam() {
		return vRam;
	}

	public void setvRam(String vRam) {
		this.vRam = vRam;
	}

	public String getvCpu() {
		return vCpu;
	}

	public void setvCpu(String vCpu) {
		this.vCpu = vCpu;
	}

	public String getvHdd() {
		return vHdd;
	}

	public void setvHdd(String vHdd) {
		this.vHdd = vHdd;
	}

	public String getOsVersion() {
		return osVersion;
	}

	public void setOsVersion(String osVersion) {
		this.osVersion = osVersion;
	}

	public String getRemarks() {
		return remarks;
	}

	public void setRemarks(String remarks) {
		this.remarks = remarks;
	}

	
	public String getPayService() {
		return payService;
	}

	public void setPayService(String payService) {
		this.payService = payService;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getManagerName() {
		return managerName;
	}

	public void setManagerName(String managerName) {
		this.managerName = managerName;
	}

	public int getStatus() {
		return status;
	}

	public void setStatus(int status) {
		this.status = status;
	}
}
