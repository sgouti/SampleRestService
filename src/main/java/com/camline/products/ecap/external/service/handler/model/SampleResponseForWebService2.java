package com.camline.products.ecap.external.service.handler.model;

import java.util.Arrays;
import java.util.Date;

public class SampleResponseForWebService2 {

    private int[] response_parameter1;
	private String[] response_parameter2;
    private long[] response_parameter3;
    private Date[] response_parameter4;
    private double[] response_parameter5;
    private int[] response_parameter6;
    private String[] response_parameter7;
    private long[] response_parameter8;
    private Date[] response_parameter9;
    private double[] response_parameter10;
    private int[] response_parameter11;
    private String[] response_parameter12;
	
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
    
    public int[] getResponse_parameter6() {
        return response_parameter6;
    }


    public void setResponse_parameter6(int[] response_parameter6) {
        this.response_parameter6 = response_parameter6;
    }


    public String[] getResponse_parameter7() {
        return response_parameter7;
    }


    public void setResponse_parameter7(String[] response_parameter7) {
        this.response_parameter7 = response_parameter7;
    }


    public long[] getResponse_parameter8() {
        return response_parameter8;
    }


    public void setResponse_parameter8(long[] response_parameter8) {
        this.response_parameter8 = response_parameter8;
    }


    public Date[] getResponse_parameter9() {
        return response_parameter9;
    }


    public void setResponse_parameter9(Date[] response_parameter9) {
        this.response_parameter9 = response_parameter9;
    }


    public double[] getResponse_parameter10() {
        return response_parameter10;
    }


    public void setResponse_parameter10(double[] response_parameter10) {
        this.response_parameter10 = response_parameter10;
    }


    public int[] getResponse_parameter11() {
        return response_parameter11;
    }


    public void setResponse_parameter11(int[] response_parameter11) {
        this.response_parameter11 = response_parameter11;
    }


    public String[] getResponse_parameter12() {
        return response_parameter12;
    }


    public void setResponse_parameter12(String[] response_parameter12) {
        this.response_parameter12 = response_parameter12;
    }
	
	@Override
	public String toString() {
		return "strings2: " + Arrays.toString(response_parameter2) + "; ints1: " + Arrays.toString(response_parameter1) + "; dates4: " + Arrays.toString(response_parameter4) + "; longs3: " + Arrays.toString(response_parameter3) + "; doubles5: " + Arrays.toString(response_parameter5) +"strings7: " + Arrays.toString(response_parameter7) + "; ints6: " + Arrays.toString(response_parameter6) + "; dates9: " + Arrays.toString(response_parameter9) + "; longs8: " + Arrays.toString(response_parameter8) + "; doubles10: " + Arrays.toString(response_parameter10) +"strings11: " + Arrays.toString(response_parameter12) + "; ints12: " + Arrays.toString(response_parameter11);
	}
}
