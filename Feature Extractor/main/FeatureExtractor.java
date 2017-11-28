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
	


    /**
     * The main method may be called by giving the directory to a single .apk or a folder containing many .apk files.
     *
     * @param args Single file or a directory
     */
	public static void main(String[] args) {
		System.out.println("Usage: java -jar FeatureExtractor.jar <Input Dir with .apk files> <Output Dir for feature files>");
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
		File input = new File(args[0]);									//Analyze just a single file or all files in a directory
		File output = new File(args[1]);									//Analyze just a single file or all files in a directory
		if (input.isDirectory()&&output.isDirectory()) {
			File[] fList = input.listFiles();
			for (File file : fList) {
				if (file.isFile() && file.getName().endsWith(".apk")) {
					analyze(file,output);
				}
			}
		}

	}

	/**
     * Creates a new instance of ManifestAnalyzer and SmaliAnalyzer and writes their findings to the outputfile
     *
     * @param input .apk to analyze
	 * @param output directory for features
     */
	private static void analyze(File input, File output) {

		System.out.println("Analyzing: " + input.getName());
		File unpackedAPK = new File(input.getName().substring(0, input.getName().length() - 4));
		File XMLManifest = new File(unpackedAPK + "/AndroidManifest.xml");
		File smaliDir = new File(unpackedAPK + "/smali");
		File featureFile = new File(output + "/"+unpackedAPK.getName()+".txt");
		try {
			Process proc = Runtime.getRuntime().exec("java -jar apktool.jar d " + input);
			proc.waitFor();

			ManifestAnalyzer mAnalyzer = new ManifestAnalyzer(XMLManifest);
			SmaliAnalyzer sAnalyzer = new SmaliAnalyzer(smaliDir.getAbsolutePath(), permissionMap, suspCallTemplate);

			writer = new PrintWriter(featureFile, "UTF-8");
			
					write(mAnalyzer.getActivities());
					write(mAnalyzer.getPermissions());
					write(mAnalyzer.getFeatures());
					write(mAnalyzer.getServiceReciever());
					write(mAnalyzer.getIntents());
					write(sAnalyzer.getApiCall());
					write(sAnalyzer.getURL());
					write(sAnalyzer.getCalls());
					write(sAnalyzer.getRealPermissions());

				

			writer.close();
			deleteFolder(unpackedAPK);

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
     * Deletes the unpacked apk after extraction
     *
     * @param folder dir to delete
     */
	public static void deleteFolder(File folder) {
	    File[] files = folder.listFiles();
	    if(files!=null) { //some JVMs return null for empty dirs
	        for(File f: files) {
	            if(f.isDirectory()) {
	                deleteFolder(f);
	            } else {
	                f.delete();
	            }
	        }
	    }
	    folder.delete();
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
