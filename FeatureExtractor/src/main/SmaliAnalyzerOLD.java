package main;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliAnalyzerOLD {
	public final static Pattern androidTelephonyPattern =  Pattern.compile("invoke-virtual .+ L(android\\/telephony\\/.+)\\(.+");
	public final static Pattern androidNetPattern =  Pattern.compile("invoke-virtual .+ L(android\\/net\\/.+)\\(.+");
	public final static Pattern androidContentPattern =  Pattern.compile("invoke-virtual .+ L(android\\/content\\/.+)\\(.+");
	public final static Pattern androidMediaPattern =  Pattern.compile("invoke-virtual .+ L(android\\/media\\/.+)\\(.+");
	public final static Pattern androidAppPattern =  Pattern.compile("invoke-virtual .+ L(android\\/app\\/.+)\\(.+");
	public final static Pattern androidWebkitPattern =  Pattern.compile("invoke-virtual .+ L(android\\/webkit\\/.+)\\(.+");
	public final static Pattern androidOSPattern =  Pattern.compile("invoke-virtual .+ L(android\\/os\\/.+)\\(.+");
	public final static Pattern androidHardwarePattern =  Pattern.compile("invoke-virtual .+ L(android\\/hardware\\/.+)\\(.+");
	public final static Pattern androidProviderPattern =  Pattern.compile("invoke-virtual .+ L(android\\/provider\\/.+)\\(.+");
	
	public final static Pattern orgApachePattern =  Pattern.compile("invoke-virtual .+ L(org\\/apache\\/.+)\\(.+");

	public final static Pattern javaPattern =  Pattern.compile("invoke-virtual .+ L(java\\/net\\/.+)\\(.+");
	public final static Pattern urlPattern =  Pattern.compile("const-string .+(http:\\/\\/.+)\"");
	public final static Pattern domainPattern =  Pattern.compile("http:\\/\\/(.+\\..*?)\\/.+");	

	private Set<String> apiCalls = new HashSet<String>();
	private Set<String> calls = new HashSet<String>();
	private Set<String> url = new HashSet<String>();
	public SmaliAnalyzerOLD(String smali) {
		try {
			search(smali);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private  void search(String directoryName) throws FileNotFoundException {
	    File directory = new File(directoryName);
	    Scanner scanner;
	    Matcher androidTelephonyMatcher;
	    Matcher androidNetMatcher;
	    Matcher androidContentMatcher;
	    Matcher androidMediaMatcher;
	    Matcher androidAppMatcher;
	    Matcher androidWebkiMatcher;
	    Matcher androidOSMatcher;
	    Matcher androidHardwareMatcher;
	    Matcher androidProviderMatcher;
	    
	    Matcher orgApacheMatcher;
	    
	    Matcher javaMatcher;
	    Matcher URLMatcher;
	    Matcher domainMatcher;

	    
	    // get all the files from a directory
	    File[] fList = directory.listFiles();
	    for (File file : fList) {
	        if (file.isFile()) {
	           System.out.println("DATEI:"+file.getName());
	           scanner = new Scanner(file);
	           while (scanner.hasNextLine()) {
	              final String lineFromFile = scanner.nextLine();

	              if(lineFromFile.contains("Landroid")&&lineFromFile.contains("invoke-virtual")) { 
	            	  androidTelephonyMatcher = androidTelephonyPattern.matcher(lineFromFile);
	            	  androidNetMatcher = androidNetPattern.matcher(lineFromFile);
	            	  androidContentMatcher = androidContentPattern.matcher(lineFromFile);
	            	  androidMediaMatcher = androidMediaPattern.matcher(lineFromFile);
	            	  androidAppMatcher = androidAppPattern.matcher(lineFromFile);
	            	  androidWebkiMatcher = androidWebkitPattern.matcher(lineFromFile);
	            	  androidOSMatcher = androidOSPattern.matcher(lineFromFile);
	            	  androidHardwareMatcher = androidHardwarePattern.matcher(lineFromFile);
	            	  androidProviderMatcher = androidProviderPattern.matcher(lineFromFile);

		              if(androidTelephonyMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidTelephonyMatcher.group(1));
		              }
		              if(androidNetMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidNetMatcher.group(1));
		              }
		              if(androidContentMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidContentMatcher.group(1));
		              }
		              if(androidMediaMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidMediaMatcher.group(1));
		              }
		              if(androidAppMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidAppMatcher.group(1));
		              }
		              if(androidWebkiMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidWebkiMatcher.group(1));
		              }
		              if(androidOSMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidOSMatcher.group(1));
		              }
		              if(androidHardwareMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidHardwareMatcher.group(1));
		              }
		              if(androidProviderMatcher.find()) {
		            	  apiCalls.add("api_call::"+androidProviderMatcher.group(1));
		              }
	              }
	              if(lineFromFile.contains("Lorg")&&lineFromFile.contains("invoke-virtual")) { 
	            	  orgApacheMatcher = orgApachePattern.matcher(lineFromFile);

		              if(orgApacheMatcher.find()) {
		            	  apiCalls.add("api_call::"+orgApacheMatcher.group(1));
		              }
	              }
	              
	              if(lineFromFile.contains("Ljava")&&lineFromFile.contains("invoke-virtual")) { 
	            	  javaMatcher = javaPattern.matcher(lineFromFile);

		              if(javaMatcher.find()) {
		            	  apiCalls.add("api_call::"+javaMatcher.group(1));
		              }
	              }
	              if(lineFromFile.contains("getPackageInfo")) {
	            	  calls.add("call::getPackageInfo");
	            	  
	              }
	              if(lineFromFile.contains("getDeviceId")) {
	            	  calls.add("call::getDeviceId");
	            	  
	              }
	              if(lineFromFile.contains("HttpPost")) {
	            	  calls.add("call::HttpPost");
	            	  
	              }
	              if(lineFromFile.contains("getSystemService")) {
	            	  calls.add("call::getSystemService");
	            	  
	              }
	              if(lineFromFile.contains("printStackTrace")) {
	            	  calls.add("call::printStackTrace");
	            	  
	              }
	              if(lineFromFile.contains("getSubscriberId")) {
	            	  calls.add("call::getSubscriberId");
	            	  
	              }
//	              if(lineFromFile.contains("exec")) {
//	            	  calls.add("call::Execution of external commands");
//	            	  
//	              }
	              if(lineFromFile.contains("setWifiEnabled")) {
	            	  calls.add("call::setWifiEnabled");
	            	  
	              }
	              if(lineFromFile.contains("getWifiState")) {
	            	  calls.add("call::getWifiState");
	            	  
	              }
	              if(lineFromFile.contains("setWifiEnabled")) {
	            	  calls.add("call::setWifiEnabled");
	            	  
	              }
	              if(lineFromFile.contains("system/bin/su")) {
	            	  calls.add("call::system/bin/su");
	            	  
	              }
	              if(lineFromFile.contains("sendTextMessage()")) {
	            	  calls.add("call::sendTextMessage");
	            	  
	              }
	              if(lineFromFile.contains("sendTextMessage()")) {
	            	  calls.add("call::sendTextMessage");
	            	  
	              }

	              
	              if(lineFromFile.contains("const-string")) {
	            	  URLMatcher = urlPattern.matcher(lineFromFile);
	            	  domainMatcher=domainPattern.matcher(lineFromFile);
		              if(URLMatcher.find()) {
		            	  url.add("url::"+URLMatcher.group(1));
		              }
		              if(domainMatcher.find()) {
		            	  url.add("url::"+domainMatcher.group(1));		            	  
		              }
	              }
	           }
	           System.out.println("");
	        } else if (file.isDirectory()) {
	            search(file.getAbsolutePath());
	        }
	    }
	}

	public  Set<String> getApiCall() {
		return apiCalls;
	}

	public Set<String> getURL() {
		return url;
	}

	public Set<String> getCalls() {
		// TODO Auto-generated method stub
		return calls;
	}

}
