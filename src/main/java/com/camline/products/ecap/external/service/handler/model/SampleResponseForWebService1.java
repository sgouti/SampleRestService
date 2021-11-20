package com.camline.products.ecap.external.service.handler.model;

import java.util.Arrays;
import java.util.Date;

public class SampleResponseForWebService1 {

    private int[] response_parameter1;
	private String[] response_parameter2;
    private long[] response_parameter3;
    private Date[] response_parameter4;
    private double[] response_parameter5;
	
	public String[] getResponse_parameter2() {
        return response_parameter2;
    }


    public void setResponse_parameter2(String[] response_parameter2) {
        this.response_parameter2 = response_parameter2;
    }


    public int[] getResponse_parameter1() {
        return response_parameter1;
    }


    public void setResponse_parameter1(int[] response_parameter1) {
        this.response_parameter1 = response_parameter1;
    }


    public Date[] getResponse_parameter4() {
        return response_parameter4;
    }


    public void setResponse_parameter4(Date[] response_parameter4) {
        this.response_parameter4 = response_parameter4;
    }


    public long[] getResponse_parameter3() {
        return response_parameter3;
    }


    public void setResponse_parameter3(long[] response_parameter3) {
        this.response_parameter3 = response_parameter3;
    }


    public double[] getResponse_parameter5() {
        return response_parameter5;
    }


    public void setResponse_parameter5(double[] response_parameter5) {
        this.response_parameter5 = response_parameter5;
    }
	
	@Override
	public String toString() {
		return "strings: " + Arrays.toString(response_parameter2) + "; ints: " + Arrays.toString(response_parameter1) + "; dates: " + Arrays.toString(response_parameter4) + "; longs: " + Arrays.toString(response_parameter3) + "; doubles: " + Arrays.toString(response_parameter5);
	}
}
