package com.camline.products.ecap.external.service.handler.model;

import java.util.Arrays;
import java.util.Date;

public class Sample {

	private String[] strings;
	private int[] ints;
	private Date[] dates;
	private long[] longs;
	private double[] doubles;

	public String[] getStrings() {
		return strings;
	}
	public void setStrings(String[] strings) {
		this.strings = strings;
	}
	public int[] getInts() {
		return ints;
	}
	public void setInts(int[] ints) {
		this.ints = ints;
	}
	public Date[] getDates() {
		return dates;
	}
	public void setDates(Date[] dates) {
		this.dates = dates;
	}	
	public long[] getLongs() {
        return longs;
    }
    public void setLongs(long[] longs) {
        this.longs = longs;
    }    
    public double[] getDoubles() {
        return doubles;
    }
    public void setDoubles(double[] doubles) {
        this.doubles = doubles;
    }

	@Override
	public String toString() {
		return "strings: " + Arrays.toString(strings) + "; ints: " + Arrays.toString(ints) + "; dates: " + Arrays.toString(dates) + "; longs: " + Arrays.toString(longs) + "; doubles: " + Arrays.toString(doubles);
	}
}
