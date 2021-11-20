package com.camline.products.ecap.external.service.handler.model;

import java.util.Date;

public class SampleRequestObject {
    private int intVal;
    private String string;
    private Date date;
    private long longValue;
    private double doubleValue;

    public SampleRequestObject(int intVal, String string, Date date) {
        this.intVal = intVal;
        this.string = string;
        this.date = date;
    }
    
    public SampleRequestObject(int intVal, String string, Date date, long longValue, double doubleValue) {
        this.intVal = intVal;
        this.string = string;
        this.date = date;
        this.longValue = longValue;
        this.doubleValue = doubleValue;
    }

    public SampleRequestObject() {
    }

    public int getIntVal() {
        return intVal;
    }

    public void setIntVal(int intVal) {
        this.intVal = intVal;
    }

    public String getString() {
        return string;
    }

    public void setString(String string) {
        this.string = string;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }
    
    public long getLongValue() {
        return longValue;
    }

    public void setLongValue(long longValue) {
        this.longValue = longValue;
    }

    public double getDoubleValue() {
        return doubleValue;
    }

    public void setDoubleValue(double doubleValue) {
        this.doubleValue = doubleValue;
    }

    @Override
    public String toString() {
        return String.format("Request:%n intVal=%d, string=%s, date=%s longValue=%d doubleValue=%f", Integer.valueOf(intVal), string, date, Long.valueOf(longValue), Double.valueOf(doubleValue));
    }
}
