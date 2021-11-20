package com.camline.products.ecap.external.service.handler.model;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

public class GetLotHistoryRequestSample {

	@JsonProperty("LotID")
    private String lotId;
	
	@JsonProperty("MaxNumSteps")
	private int maxNumSteps;
	
	@JsonProperty("NotOlderThan")
    private Date notOlderThan;
    
	/**
	 * @return the lotId
	 */
	public String getLotId() {
		return lotId;
	}
	
	/**
	 * @param lotId the lotId to set
	 */
	public void setLotId(String lotId) {
		this.lotId = lotId;
	}
	
	/**
	 * @return the maxNumSteps
	 */
	public int getMaxNumSteps() {
		return maxNumSteps;
	}
	
	/**
	 * @param maxNumSteps the maxNumSteps to set
	 */
	public void setMaxNumSteps(int maxNumSteps) {
		this.maxNumSteps = maxNumSteps;
	}
	
	
	/**
	 * @return the notOlderThan
	 */
	public Date getNotOlderThan() {
		return notOlderThan;
	}

	/**
	 * @param notOlderThan the notOlderThan to set
	 */
	public void setNotOlderThan(Date notOlderThan) {
		this.notOlderThan = notOlderThan;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "GetLotHistoryRequestSample [lotId=" + lotId + ", maxNumSteps=" + maxNumSteps + ", noOlderThan="
				+ notOlderThan + "]";
	}
}
