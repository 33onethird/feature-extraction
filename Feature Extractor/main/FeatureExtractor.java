package main;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *This is the main class, which organizes the analyzation of given .apk files.
 *It requires apktool.jar, jellybean_allmappings.txt and apicalls_suspicious.txt"to be placed in the same directory.
 *The output is a new folder per app, containing the extracted Features.txt
 *
 * @author Philipp Adam
 * @version 1.0 9/11/17
 */
public class FeatureExtractor {
	public final static Pattern callPattern = Pattern.compile("<(.*): .* (.+)\\(.*\\(");	 //For parsing the jellybean_mappings.txt
	public final static File mappings = new File("jellybean_allmappings.txt");
	public final static File suspicoiusCalls = new File("apicalls_suspicious.txt");
	private static HashMap<String, String> permissionMap;								//Datastructure mapping MethodCalls <-> Permission(s)
	private static Set<String> suspCallTemplate = new HashSet<String>();				//Datastructure containing a list of suspicious calls		
	private static PrintWriter writer;
	private static boolean noNames = false;
	private static ArrayList<String> cutOuts =new ArrayList<String>();
	
	private static boolean noActivity= false;
	private static boolean noPermission= false;
	private static boolean noFeature= false;
	private static boolean noIntent= false;
	private static boolean noService_receiver= false;
	private static boolean noApi_call= false;
	private static boolean noURL= false;
	private static boolean noCall= false;
	private static boolean noReal_permission= false;

    /**
     * The main method may be called by giving the directory to a single .apk or a folder containing many .apk files.
     *
     * @param args Single file or a directory
     */
	public static void main(String[] args) {
		System.out.println("Usage: java -jar FeatureExtractor.jar <SingeAPK> OR <Directory with APKs>");
		try {
			permissionMap = buildPermissionMap(mappings);	
			Scanner scannerCalls = new Scanner(suspicoiusCalls);
			while (scannerCalls.hasNextLine()) {
				suspCallTemplate.add(scannerCalls.nextLine());
			}
			scannerCalls.close();
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		if(args.length>1) {
			if(args[1].equals("nonames")) {
				noNames=true;
			}
			if(args[1].equals("cut")&&args.length>2) {
				for(int i =2;i<args.length;i++) {
					cutOuts.add(args[i]);
				}
				if(cutOuts.contains("activity")) {
					noActivity=true;
				}
				if(cutOuts.contains("permission")) {
					noPermission=true;
				}
				if(cutOuts.contains("feature")) {
					noFeature=true;
				}
				if(cutOuts.contains("intent")) {
					noIntent=true;
				}
				if(cutOuts.contains("service_receiver")) {
					noService_receiver=true;
				}
				if(cutOuts.contains("api_call")) {
					noApi_call=true;
				}
				if(cutOuts.contains("url")) {
					noURL=true;
				}
				if(cutOuts.contains("call")) {
					noCall=true;
				}
				if(cutOuts.contains("real_permission")) {
					noReal_permission=true;
				}
			}
		}
		File input = new File(args[0]);									//Analyze just a single file or all files in a directory
		if (input.isFile() && input.getName().endsWith(".apk")) {
			analyze(input);
		}
		if (input.isDirectory()) {
			File[] fList = input.listFiles();
			for (File file : fList) {
				if (file.isFile() && file.getName().endsWith(".apk")) {
					analyze(file);
				}
			}
		}

	}
    /**
     * Creates a new instance of ManifestAnalyzer and SmaliAnalyzer and writes their findings to the outputfile
     *
     * @param input .apk to analyze
     */
	private static void analyze(File input) {

		System.out.println("Analyzing: " + input.getName());
		File outputdir = new File(input.getName().substring(0, input.getName().length() - 4));
		File XMLManifest = new File(outputdir + "/AndroidManifest.xml");
		File smaliDir = new File(outputdir + "/smali");
		File featureFile = new File(outputdir + "/Features.txt");
		try {
			Process proc = Runtime.getRuntime().exec("java -jar apktool.jar d " + input);
			proc.waitFor();

			ManifestAnalyzer mAnalyzer = new ManifestAnalyzer(XMLManifest);
			SmaliAnalyzer sAnalyzer = new SmaliAnalyzer(smaliDir.getAbsolutePath(), permissionMap, suspCallTemplate);

			writer = new PrintWriter(featureFile, "UTF-8");
			
			if(noNames) {
				write(mAnalyzer.getPermissions());
				write(mAnalyzer.getFeatures());
				write(sAnalyzer.getApiCall());
				write(sAnalyzer.getCalls());
				write(sAnalyzer.getRealPermissions());
			}else  {
				if(!noActivity) {
					write(mAnalyzer.getActivities());
				}
				if(!noPermission) {
					write(mAnalyzer.getPermissions());
				}
				if(!noFeature) {
					write(mAnalyzer.getFeatures());
				}
				if(!noService_receiver) {
					write(mAnalyzer.getServiceReciever());
				}
				if(!noIntent) {
					write(mAnalyzer.getIntents());
				}
				if(!noApi_call) {
					write(sAnalyzer.getApiCall());
				}
				if(!noURL) {
					write(sAnalyzer.getURL());
				}
				if(!noCall) {
					write(sAnalyzer.getCalls());
				}
				if(!noReal_permission) {
					write(sAnalyzer.getRealPermissions());
				}
				
			}
			writer.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}
    /**
     * Convenience method to write a set of features to a file
     *
     * @param lines set to write
     */
	private static void write(Set<String> lines) {
		for (String line : lines) {
			writer.println(line);
		}
	}
    /**
     * Reads the jellybean_allmappings.txt file and parses it to build a map with the functionality to get all required permissions (value) per API call (key)
     *
     * @param mappingsFile jellybean_allmappings.txt file
     * @return permissionMap converted datastructure
     * @throws FileNotFoundException If the file is missing
     */
	private static HashMap<String, String> buildPermissionMap(File mappingsFile) throws FileNotFoundException {
		HashMap<String, String> permissionMap = new HashMap<String, String>();
		Scanner scannerMappings = new Scanner(mappingsFile);

		String permission = "";
		String call = "";
		Matcher callMatcher;
		while (scannerMappings.hasNextLine()) {
			String lineFromFile = scannerMappings.nextLine();
			if (lineFromFile.startsWith("Permission")) {
				permission = lineFromFile.substring(11);
			}
			if (lineFromFile.startsWith("<")) {
				callMatcher = callPattern.matcher(lineFromFile);
				callMatcher.find();
				String javaClass = callMatcher.group(1).replace(".", "/");  //to match the format in the decompiled code
				String javaMethod = callMatcher.group(2);
				call = javaClass + ";->" + javaMethod;		//to match the format in the decompiled code
			}
			if (!permission.equals("") && !call.equals("")) {
				if (permissionMap.containsKey(call)) {						//if a call requires more permissions, link them together with "-" 
					String previousPermission = permissionMap.get(call);		
					permissionMap.remove(call);
					permissionMap.put(call, previousPermission + "-" + permission);
				} else {
					permissionMap.put(call, permission);
				}

			}
		}
		scannerMappings.close();
		return permissionMap;
	}

}
