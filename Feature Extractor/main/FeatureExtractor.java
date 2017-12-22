package main;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is the main class, which organizes the analyzation of given .apk files.
 * It requires apktool.jar, jellybean_allmappings.txt and
 * apicalls_suspicious.txt"to be placed in the same directory. The output is a
 * new folder per app, containing the extracted Features.txt
 *
 * @author Philipp Adam
 * @version 1.0 9/11/17
 */
public class FeatureExtractor {
	public final static Pattern callPattern = Pattern.compile("<(.*): .* (.+)\\(.*\\("); // For parsing the
																							// jellybean_mappings.txt
	public final static File mappings = new File("jellybean_allmappings.txt");
	public final static File suspicoiusCalls = new File("apicalls_suspicious.txt");
	private static HashMap<String, String> permissionMap; // Datastructure mapping MethodCalls <-> Permission(s)
	private static Set<String> suspCallTemplate = new HashSet<String>(); // Datastructure containing a list of
																			// suspicious calls
	private static PrintWriter writer;
	private static long timeOuts = 0;

	/**
	 * The main method may be called by giving the directory to a single .apk or a
	 * folder containing many .apk files.
	 *
	 * @param args
	 *            Single file or a directory
	 */
	public static void main(String[] args) {
		System.out.println("Usage: java -jar FeatureExtractor.jar <Input Dir> <Output Dir for feature files>");
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
		File input = new File(args[0]); // Analyze just a single file or all files in a directory
		File output = new File(args[1]); // Analyze just a single file or all files in a directory
		if (input.isDirectory() && output.isDirectory()) {
			File[] fList = input.listFiles();
			for (File file : fList) {
				if (file.isFile()) {
					analyze(file, output);
				}
			}
		}
		System.out.println("APPS SKIPPED:" + timeOuts);

	}

	/**
	 * Creates a new instance of ManifestAnalyzer and SmaliAnalyzer and writes their
	 * findings to the outputfile
	 *
	 * @param input
	 *            .apk to analyze
	 * @param output
	 *            directory for features
	 */
	private static void analyze(File input, File output) {

		System.out.println("Analyzing: " + input.getName());
		File unpackedAPK = new File(input.getName());
		File XMLManifest = new File(unpackedAPK + "/AndroidManifest.xml");
		File smaliDir = new File(unpackedAPK + "/smali");
		File featureFile = new File(output + "/" + input.getName() + ".txt");
		try {
			Process proc = Runtime.getRuntime().exec("java -jar apktool.jar d -o " + unpackedAPK + " " + input);
			// proc.waitFor();
			if (!proc.waitFor(30, TimeUnit.SECONDS)) {
				// timeout - kill the process.
				proc.destroy(); // consider using destroyForcibly instead
				System.out.println("TIMEOUT");
				timeOuts++;
				return;
			}

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
	 * @param lines
	 *            set to write
	 */
	private static void write(Set<String> lines) {
		for (String line : lines) {
			writer.println(line);

		}
	}

	/**
	 * Deletes the unpacked apk after extraction
	 *
	 * @param folder
	 *            dir to delete
	 */
	public static void deleteFolder(File folder) {
		File[] files = folder.listFiles();
		if (files != null) { // some JVMs return null for empty dirs
			for (File f : files) {
				if (f.isDirectory()) {
					deleteFolder(f);
				} else {
					f.delete();
				}
			}
		}
		folder.delete();
	}

	/**
	 * Reads the jellybean_allmappings.txt file and parses it to build a map with
	 * the functionality to get all required permissions (value) per API call (key)
	 *
	 * @param mappingsFile
	 *            jellybean_allmappings.txt file
	 * @return permissionMap converted datastructure
	 * @throws FileNotFoundException
	 *             If the file is missing
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
				String javaClass = callMatcher.group(1).replace(".", "/"); // to match the format in the decompiled code
				String javaMethod = callMatcher.group(2);
				call = javaClass + ";->" + javaMethod; // to match the format in the decompiled code
			}
			if (!permission.equals("") && !call.equals("")) {
				if (permissionMap.containsKey(call)) { // if a call requires more permissions, link them together with
														// "-"
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
