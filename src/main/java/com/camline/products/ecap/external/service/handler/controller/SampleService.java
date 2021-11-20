package com.camline.products.ecap.external.service.handler.controller;

import java.util.Date;
import java.util.GregorianCalendar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.camline.products.ecap.external.service.handler.model.GetLotHistoryRequestSample;
import com.camline.products.ecap.external.service.handler.model.GetLotHistoryResponseSample;
import com.camline.products.ecap.external.service.handler.model.Sample;
import com.camline.products.ecap.external.service.handler.model.SampleRequestForWebService1;
import com.camline.products.ecap.external.service.handler.model.SampleRequestForWebService2;
import com.camline.products.ecap.external.service.handler.model.SampleRequestObject;
import com.camline.products.ecap.external.service.handler.model.SampleResponseForWebService1;
import com.camline.products.ecap.external.service.handler.model.SampleResponseForWebService2;

@RestController
public class SampleService {
	
	final static Logger logger = LoggerFactory.getLogger(SampleService.class);

	@GetMapping("/sample")
	public Sample getSample() {
		Sample sample = new Sample();
		sample.setInts(new int [] {1,2,3,4});
		sample.setDates(new Date[] {GregorianCalendar.getInstance().getTime()});
		sample.setStrings(new String[]{"BLR1,BLR2,BLR3,BLR4"});
		return sample;
	}

	@GetMapping(value = {"/in3out2Get"})
	public Sample in3out2Get(@RequestParam("in1") String in1, @RequestParam("in2") int in2, @RequestParam("in3") int in3) {
		logger.info("***************************************** Params: " + in1 + ", " + in2 + ", " + in3);
		Sample sample = new Sample();
		sample.setStrings(new String[]{in1});
		sample.setInts(new int[]{in2, in3});
		sample.setDates(new Date[] {GregorianCalendar.getInstance().getTime()});
		return sample;
	}

	@PostMapping(value=  {"/in3out2Post"}, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
	public Sample in3out2Post(@RequestBody SampleRequestObject request) {
		logger.info("***************************************** Params: " + request);
		Sample sample = new Sample();
		sample.setDates(new Date[] {request.getDate(), GregorianCalendar.getInstance().getTime()});
        sample.setStrings(new String[] {request.getString(), ""+Math.random()});
        sample.setInts(new int[] {request.getIntVal(), (int)(1000*Math.random())});
		return sample;
	}
	
	@PostMapping(value=  {"/in5out5Post"}, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public SampleResponseForWebService1 in5out5Post(@RequestBody SampleRequestForWebService1 request) {
		logger.info("***************************************** Params: " + request);
        SampleResponseForWebService1 sample = new SampleResponseForWebService1();
        sample.setResponse_parameter1(new int[] {request.getRequest_parameter2(), (int)(1000*Math.random())});
        sample.setResponse_parameter2(new String[] {request.getRequest_parameter1(), ""+Math.random()});
        sample.setResponse_parameter3(new long[] {request.getRequest_parameter4(), (long)(1000*Math.random())});
        sample.setResponse_parameter4(new Date[] {request.getRequest_parameter3(), GregorianCalendar.getInstance().getTime()});
        sample.setResponse_parameter5(new double[] {request.getRequest_parameter5(), (double)(1000*Math.random())});        
        return sample;
    }
	
	@PostMapping(value=  {"/in12out12Post"}, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public SampleResponseForWebService2 in12out12Post(@RequestBody SampleRequestForWebService2 request) {
		logger.info("***************************************** Params for in12out12Post : " + request);
        SampleResponseForWebService2 sample = new SampleResponseForWebService2();
        sample.setResponse_parameter1(new int[] {request.getRequest_parameter2(), (int)(1000*Math.random())});
        sample.setResponse_parameter2(new String[] {request.getRequest_parameter1(), ""+Math.random()});
        sample.setResponse_parameter3(new long[] {request.getRequest_parameter4(), (long)(1000*Math.random())});
        sample.setResponse_parameter4(new Date[] {request.getRequest_parameter3(), GregorianCalendar.getInstance().getTime()});
        sample.setResponse_parameter5(new double[] {request.getRequest_parameter5(), (double)(1000*Math.random())});
        sample.setResponse_parameter6(new int[] {request.getRequest_parameter7(), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random())});
        sample.setResponse_parameter7(new String[] {request.getRequest_parameter6(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random()});
        sample.setResponse_parameter8(new long[] {request.getRequest_parameter9(), (long)(1000*Math.random()), (long)(1000*Math.random()), (long)(1000*Math.random()), (long)(1000*Math.random())});
        sample.setResponse_parameter9(new Date[] {request.getRequest_parameter8(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime()});
        sample.setResponse_parameter10(new double[] {request.getRequest_parameter10(), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random()), (double)(1000*Math.random())});
        sample.setResponse_parameter11(new int[] {request.getRequest_parameter12(), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random()), (int)(1000*Math.random())});
        sample.setResponse_parameter12(new String[] {request.getRequest_parameter1(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random(), ""+Math.random()});
        return sample;
    }

	
	@PostMapping(value=  {"/GetLotHistory"}, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public GetLotHistoryResponseSample GetLotHistory(@RequestBody GetLotHistoryRequestSample request) {
		logger.info("***************************************** Params: " + request);
        GetLotHistoryResponseSample sample = new GetLotHistoryResponseSample();
        sample.setSteps(new int[] {5, 4, 3, 2, 1});
        sample.setpToolId(new String[] {"WE33", "SP16", "CL72", "LT02", "CL27"});
        sample.setTimeStamp(new Date[] {GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime()});
        return sample;
    }
	
	@GetMapping(value=  {"/GetLotHistoryUsingQueryParam"}, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public GetLotHistoryResponseSample getTemplateUsingQueryParam(@RequestParam(name="LotID") String lotId, @RequestParam(name="MaxNumSteps") String maxNumSteps) {     
		logger.info("***************************************** Query Params: LotID=" + lotId + " MaxNumSteps=" + maxNumSteps);
        GetLotHistoryResponseSample sample = new GetLotHistoryResponseSample();
        sample.setSteps(new int[] {3, 2, 1});
        sample.setpToolId(new String[] {"PTool_01_" + lotId, "PTool_02_" + lotId, "PTool_03_" + lotId});
        sample.setTimeStamp(new Date[] {GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime()});
     
        return sample;
    }

	@GetMapping(value=  {"/GetLotHistoryUsingURIParam/{LotID}/{MaxNumSteps}"}, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public GetLotHistoryResponseSample getInstanceUsingURIParam(@PathVariable("LotID") String lotId, @PathVariable("MaxNumSteps") Integer maxNumSteps) {     
		logger.info("***************************************** URI Params: LotID=" + lotId);
        GetLotHistoryResponseSample sample = new GetLotHistoryResponseSample();
        sample.setSteps(new int[] {1});
        sample.setpToolId(new String[] {"PTool_" + lotId + " MaxNumSteps=" + maxNumSteps});
        sample.setTimeStamp(new Date[] {GregorianCalendar.getInstance().getTime()});
     
        return sample;
    }
	
	//Currently this one is not supported (URI and Query Parameters)
	@GetMapping(value = { "/GetLotHistoryUsingURIQueryParam/{LotID}/{MaxNumSteps}"}, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public GetLotHistoryResponseSample getInstanceUsingURIQueryParam(@PathVariable("LotID") String lotId,
	        @PathVariable("MaxNumSteps") Integer maxNumSteps, @RequestParam(name = "LotID") String qlotId,
	        @RequestParam(name = "MaxNumSteps") String qmaxNumSteps) {
		logger.info("***************************************** URI & Query Params: LotID=" + lotId);
		GetLotHistoryResponseSample sample = new GetLotHistoryResponseSample();
		sample.setSteps(new int[] { maxNumSteps.intValue() });
		sample.setpToolId(new String[] { "PTool_URI_" + lotId + "_QUERY_" + qlotId});
		sample.setTimeStamp(new Date[] { GregorianCalendar.getInstance().getTime()});
		return sample;
	}
	//Added by Siddharth for Testing

	@PostMapping(value=  {"/PostLotHistory/{SectionID}"}, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public GetLotHistoryResponseSample PostLotHistory(@PathVariable("SectionID") String sectionID,@RequestBody GetLotHistoryRequestSample request) {
		logger.info("***************************************** Params: " + request);
        GetLotHistoryResponseSample sample = new GetLotHistoryResponseSample();
        sample.setSteps(new int[] {1, 2, 3, 4, request.getMaxNumSteps()});
        sample.setpToolId(new String[] {"LTD01", "LTD02", "LTD03", "LTD04", "LTD05",request.getLotId()});
        sample.setTimeStamp(new Date[] {GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(),request.getNotOlderThan()});
        return sample;
    }
	@PostMapping(value=  {"/PostLotHistorywithName/{LotID}/Delay"}, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public GetLotHistoryResponseSample PostLotHistoryWithOptional(@PathVariable(name="LotID",required = false) String lotId,@RequestBody GetLotHistoryRequestSample request) {
		logger.info("***************************************** Params: " + request);
       GetLotHistoryResponseSample sample = new GetLotHistoryResponseSample();
       try {
		Thread.sleep(8000);
	} catch (InterruptedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
       String username = StringUtils.isEmpty(request.getLotId()) ? "MTE003" : request.getLotId();
       sample.setSteps(new int[] {1, 2, 3, 4,5,6 });
        sample.setpToolId(new String[] {"LTD013", "LTD02", "LTD03", "LTD04", "LTD05",username});
        sample.setTimeStamp(new Date[] {GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime(), GregorianCalendar.getInstance().getTime()});
        return sample;
    }

}
