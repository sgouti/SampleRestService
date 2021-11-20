package com.camline.products.ecap.external.service.handler.model;

import java.util.Arrays;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

public class GetLotHistoryResponseSample {

	@JsonProperty("Steps")
	private int[] steps;
	
	@JsonProperty("PToolID")
	private String[] pToolId;
	
	@JsonProperty("TimeStamp")
    private Date[] timeStamp;

    /**
	 * @return the steps
	 */
	public int[] getSteps() {
		return steps;
	}

	/**
	 * @param steps the steps to set
	 */
	public void setSteps(int[] steps) {
		this.steps = steps;
	}

	/**
	 * @return the pToolId
	 */
	public String[] getpToolId() {
		return pToolId;
	}

	/**
	 * @param pToolId the pToolId to set
	 */
	public void setpToolId(String[] pToolId) {
		this.pToolId = pToolId;
	}

	/**
	 * @return the timeStamp
	 */
	public Date[] getTimeStamp() {
		return timeStamp;
	}

	/**
	 * @param timeStamp the timeStamp to set
	 */
	public void setTimeStamp(Date[] timeStamp) {
		this.timeStamp = timeStamp;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "GetLotHistoryResponseSample [steps=" + Arrays.toString(steps) + ", pToolId=" + Arrays.toString(pToolId)
				+ ", timeStamp=" + Arrays.toString(timeStamp) + "]";
	}

}
