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
/**
 *This class analyzes the decompiled code 
 *
 * @author Philipp Adam
 * @version 1.0 9/11/17
 */
public class SmaliAnalyzer {

	public final static Pattern urlPattern = Pattern.compile("const-string .+(http:\\/\\/.+)\"");				//Regex patterns for URLs
	public final static Pattern domainPattern = Pattern.compile("http:\\/\\/(.+\\..*?)\\/.+");
	public final static Pattern urlHTTPSPattern = Pattern.compile("const-string .+(https:\\/\\/.+)\"");
	public final static Pattern domainHTTPSPattern = Pattern.compile("https:\\/\\/(.+\\..*?)\\/.+");
	
	public final static Pattern cipherPattern = Pattern.compile("const-string.*\\\"(.*)\\\"");		//Regex for details on Cipher

	private static HashMap<String, String> permissionMap;	//Datastructure mapping MethodCalls <-> Permission(s)
	private static Set<String> suspCallSet;			//Datastructure containing a list of suspicious calls	
	private static Set<String> callTemplate;		//Datastructure containing a list of all apiCalls worthy for extraction

	private Set<String> apiCalls = new HashSet<String>();
	private Set<String> calls = new HashSet<String>();
	private Set<String> url = new HashSet<String>();
	private Set<String> realPermission = new HashSet<String>();
	
    /**
     * Uses the prebuilt mapping and list to initialize the analysis and selects the real permissions used by looking up every extracted api call in the map MethodCalls <-> Permission(s)
     *
     * @param smali Folder with decompiled code
     * @param prebuiltPermissionMap Datastructure mapping MethodCalls <-> Permission(s)
     * @param prebuiltSuspCallTemplate list of suspicious calls	 
     */
	
	public SmaliAnalyzer(String smali, HashMap<String, String> prebuiltPermissionMap,
			Set<String> prebuiltSuspCallTemplate) {
		System.out.println("ANALYZING DECOMPILED CODE");
		try {
			permissionMap = prebuiltPermissionMap;
			suspCallSet = prebuiltSuspCallTemplate;
			callTemplate = permissionMap.keySet();
			search(smali);

			for (String call : apiCalls) {
				call = call.substring(10);// omit api_call::
				if (permissionMap.containsKey(call)) {
					for (String permission : splitToList(permissionMap.get(call))) { //if a call requires more than one permission, split the string to an iterable list
						realPermission.add("real_permission::" + permission);
					}
				}
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
    /**
     * Convenience method to split a string of many permissions to a list e.g. "android.permission.INTERNET-android.permission.RECEIVE_BOOT_COMPLETED" to [android.permission.INTERNET,android.permission.RECEIVE_BOOT_COMPLETED]
     *
     * @param string the string to split
     * @return result list of permissions
     */
	private static ArrayList<String> splitToList(String string) {
		ArrayList<String> result = new ArrayList<String>();
		while (true) {
			if (string.contains("-")) {
				result.add(string.split("-", 2)[0]);
				string = string.split("-", 2)[1];
			} else {
				result.add(string);
				break;
			}
		}
		return result;
	}

    /**
     *Recursive method that analyzes all files in its directory and subdirectories and stores its findings in sets
     *
     * @param directoryName initial directory
     * @throws FileNotFoundException if directory is missing
     */
	private void search(String directoryName) throws FileNotFoundException {
		File directory = new File(directoryName);
		Scanner scanner;
		Matcher URLMatcher;
		Matcher domainMatcher;
		Matcher URLHTTPSMatcher;
		Matcher domainHTTPSMatcher;
		Matcher cipherMatcher;
		String previous = "";

		File[] fList = directory.listFiles();
		for (File file : fList) {
			if (file.isFile()) {
				System.out.println("CURRENT FILE: " + file.getName());
				scanner = new Scanner(file);
				while (scanner.hasNextLine()) {
					final String lineFromFile = scanner.nextLine();
					if (!lineFromFile.equals("")) {					//Don't bother with empty lines
						for (String call : callTemplate) {			
							if (lineFromFile.contains(call)) {		//If the current line contains a relevant api call
								apiCalls.add("api_call::" + call);
								break;
							}
						}
						for (String suspCall : suspCallSet) {
							if (lineFromFile.contains(suspCall)) {   //If the current line contains a suspicious api call
								if (lineFromFile.contains("Cipher")) { 		//If it is a cipher, look at the previous line to get more information e.b. Cipher(RSA/ECB/PKCS1Padding)
									cipherMatcher = cipherPattern.matcher(previous);
									if (cipherMatcher.find()) {
										calls.add("call::Cipher(" + cipherMatcher.group(1) + ")");
									}
								} else {
									calls.add("call::" + suspCall);
								}
								break;
							}

						}

						if (lineFromFile.contains("const-string")) {
							URLMatcher = urlPattern.matcher(lineFromFile);
							domainMatcher = domainPattern.matcher(lineFromFile);
							URLHTTPSMatcher = urlHTTPSPattern.matcher(lineFromFile);
							domainHTTPSMatcher = domainHTTPSPattern.matcher(lineFromFile);
							if (URLMatcher.find()) {
								url.add("url::" + URLMatcher.group(1));
							}
							if (domainMatcher.find()) {
								url.add("url::" + domainMatcher.group(1));
							}
							if (URLHTTPSMatcher.find()) {
								url.add("url::" + URLHTTPSMatcher.group(1));
							}
							if (domainHTTPSMatcher.find()) {
								url.add("url::" + domainHTTPSMatcher.group(1));
							}
						}

						previous = lineFromFile;
					}
				}
			} else if (file.isDirectory()) {
				search(file.getAbsolutePath());
			}
		}
	}

	public Set<String> getApiCall() {
		return apiCalls;
	}

	public Set<String> getURL() {
		return url;
	}

	public Set<String> getCalls() {
		return calls;
	}

	public Set<String> getRealPermissions() {
		return realPermission;
	}

}
