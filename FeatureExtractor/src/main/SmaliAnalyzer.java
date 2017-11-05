package main;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmaliAnalyzer {

	public final static Pattern urlPattern =  Pattern.compile("const-string .+(http:\\/\\/.+)\"");
	public final static Pattern domainPattern =  Pattern.compile("http:\\/\\/(.+\\..*?)\\/.+");	
	public final static Pattern callPattern =  Pattern.compile("<(.*): .* (.+)\\(.*\\(");	
	public final static File mappings = new File("jellybean_allmappings.txt");
	private static HashSet<String> callTemplate = new HashSet<String>();
	
	private Set<String> apiCalls = new HashSet<String>();
	private Set<String> calls = new HashSet<String>();
	private Set<String> url = new HashSet<String>();
	private Set<String> realPermission=new HashSet<String>();
    private File apiCalltags = new File("api_call_tags.txt");
	public SmaliAnalyzer(String smali) {
		try {
			Scanner scanner = new Scanner(apiCalltags);
			
	           while (scanner.hasNextLine()) {
	        	   String lineFromFile = scanner.nextLine();
	        	   callTemplate.add(lineFromFile.substring(10)); // omit api_call::
	           }

			search(smali);
			HashMap<String,String> permissionMap = buildPermissionMap(mappings);
			
			for(String call:apiCalls) {
				call=call.substring(10);// omit api_call::
				if(permissionMap.containsKey(call)) {
					for(String permission : splitToList(permissionMap.get(call))){
						//System.out.println("ADDING:"+permission);
						realPermission.add("real_permission::"+permission);
					}
				}
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private static HashMap<String, String> buildPermissionMap(File mappingsFile) throws FileNotFoundException {
		HashMap<String,String> permissionMap = new HashMap<String,String>();
		Scanner scannerMappings = new Scanner(mappingsFile);
		
		String permission="";
		String call="";
		Matcher callMatcher;
		while (scannerMappings.hasNextLine()) {
    	   String lineFromFile = scannerMappings.nextLine();
    	   	if(lineFromFile.startsWith("Permission")) {
    	   		permission=lineFromFile.substring(11);
    	   	}
    	   	if(lineFromFile.startsWith("<")) {
    	   		 callMatcher= callPattern.matcher(lineFromFile);
    	   		 callMatcher.find();
    	   		 String javaClass= callMatcher.group(1).replace(".", "/");
    	   		 String javaMethod=callMatcher.group(2);
    	   		 call=javaClass+";->"+javaMethod;
    	   	}
    	   if(!permission.equals("")&&!call.equals("")) {
    		   if(permissionMap.containsKey(call)) {
    			   String previousPermission=permissionMap.get(call);
    			   permissionMap.remove(call);
        		   permissionMap.put(call, previousPermission+"-"+permission);
    		   }else {
        		   permissionMap.put(call, permission);
    		   }

    	   }
       }
		
		return permissionMap;
	}
	private static ArrayList<String> splitToList(String string) {
		ArrayList<String> result = new ArrayList<String>();
		while(true) {
		//	System.out.println("String: "+string);
			if(string.contains("-")) {
				result.add(string.split("-",2)[0]);
				string=string.split("-",2)[1];
				//System.out.println("SPLITIED! new string:"+string);
			}else{
				//System.out.println("nothing to split");
				result.add(string);
				break;
			}
		}
		return result;
	}
	private  void search(String directoryName) throws FileNotFoundException {
	    File directory = new File(directoryName);
	    Scanner scanner;
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
	              for(String call:callTemplate) {
	            	  if(lineFromFile.contains(call)) {
	            		//  System.out.println(lineFromFile+" contains "+call);
	            		  apiCalls.add("api_call::"+call);
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
	public Set<String> getRealPermissions() {
		// TODO Auto-generated method stub
		return realPermission;
	}

}
