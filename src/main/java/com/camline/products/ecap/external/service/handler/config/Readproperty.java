package com.camline.products.ecap.external.service.handler.config;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

public class Readproperty {
	private static Properties prop = new Properties();
	public static  void SetProperty(String Key,String values) 
	{

		//Load the gf.properties file only
		
		try (OutputStream output = new FileOutputStream(".//src/main/resources/TestData.properties")) {
 
            
            // set the properties value
            prop.put(Key, values);
           
            // save properties to project root folder
            prop.store(output, "updated for localhost");
            
            output.flush();
            System.out.println(GetProperty(Key));
            output.close();

        } catch (IOException io) {
            io.printStackTrace();
        
        }
		
	}	

	public static String GetProperty(String key)
	{
		try (InputStream input=new FileInputStream(".//src/main/resources/TestData.properties")) {

		prop.load(input);
			}
		catch (IOException io) {
            io.printStackTrace();
        
        }
		return prop.getProperty(key);
	}

}
