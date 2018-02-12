import java.io.File;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is the main class, which organizes the analyzation of given .apk files.
 * It requires apktool.jar, jellybean_allmappings.txt and
 * apicalls_suspicious.txt"to be placed in the same directory. The output is a
 * new file per app, containing the extracted features
 *
 * @author Philipp Adam
 * @version 2.0 12/2/18
 */
public class FeatureExtractor {
	private final static File MAPPINGS = new File("jellybean_allmappings.txt");
	private final static File SUSPICIOUSAPICALLS = new File("apicalls_suspicious.txt");
	private final static Pattern CALLPATTERN = Pattern.compile("<(.*): .* (.+)\\(.*\\(");
	private static final int NUMBER_OF_UNPACKEDPRODUCERS = 4; // Number of threads unpacking APKs
	private static final int NUMBER_OF_ANALYZERS = 8; // Number of threads analyzing unpacked APKs
	private static final int PACKEDQUEUE_SIZE = 1000;
	private static final int UNPACKEDQUEUE_SIZE = 40;

	private static BlockingQueue<File> packedAPKs; // APKs to unpack
	private static BlockingQueue<File> unpackedAPKs; // Unpacked APKs to analyze
	private static Collection<Thread> packedProducerCollection, unpackedProducerThreadCollection, allThreadCollection;
	private static HashMap<String, String> permissionMap;
	private static Set<String> suspCallTemplate = new HashSet<String>();

	/**
	 * The main method may be called by giving the input directory of APKs and the
	 * outputdirectory for the feature files
	 * 
	 * @param args
	 *            Input and Output directory
	 */
	public static void main(String[] args) throws IOException {
		System.out.println("Usage: java -jar FeatureExtractor.jar <Input Dir> <Output Dir for feature files>");
		try {
			permissionMap = buildPermissionMap(MAPPINGS);
			Scanner scannerCalls = new Scanner(SUSPICIOUSAPICALLS);
			while (scannerCalls.hasNextLine()) {
				suspCallTemplate.add(scannerCalls.nextLine());
			}
			scannerCalls.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		File input = new File(args[0]);
		File output = new File(args[1]);

		if (input.isDirectory() && output.isDirectory()) {
			unpackedProducerThreadCollection = new ArrayList<Thread>();
			packedProducerCollection = new ArrayList<Thread>();
			allThreadCollection = new ArrayList<Thread>();
			packedAPKs = new LinkedBlockingDeque<File>(PACKEDQUEUE_SIZE);
			unpackedAPKs = new LinkedBlockingDeque<File>(UNPACKEDQUEUE_SIZE);
			createAndStartPackedQueue(input);
			createAndStartUnpackedProducers();
			createAndStartConsumers(output);

			for (Thread t : allThreadCollection) {
				try {
					t.join();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		System.out.println("----------------------- ANALYSIS COMPLETED-----------------------");
	}

	/**
	 * Creates a new instance of packedProducer, which adds the packed APKs to the
	 * unpacking queue
	 *
	 * @param input
	 *            Input directory
	 */
	private static void createAndStartPackedQueue(File input) throws IOException {
		PackedProducer packedProducer = new PackedProducer(input.getCanonicalPath(), packedAPKs);
		Thread producerThread = new Thread(packedProducer, "PACKEDPRODUCER");
		packedProducerCollection.add(producerThread);
		producerThread.start();
		allThreadCollection.addAll(packedProducerCollection);
	}

	/**
	 * Creates several new instances of UnpackedProducer, which unpack files from
	 * packedAPKs queue and add the unpacked APKs to the unpackedAPKs queue.
	 */
	private static void createAndStartUnpackedProducers() throws IOException {
		for (int i = 0; i < NUMBER_OF_UNPACKEDPRODUCERS; i++) {
			UnpackedProducer unpackedProducer = new UnpackedProducer(packedAPKs, unpackedAPKs);
			Thread producerThread = new Thread(unpackedProducer, "UNPACKED APKPRODUCER");
			unpackedProducerThreadCollection.add(producerThread);
			producerThread.start();

		}
		allThreadCollection.addAll(unpackedProducerThreadCollection);

	}
	/**
	 * Creates several new instances of APKAnalyzer, which organize the analyzation of unpacked APKs
	 * and the writing into the feature file
	 * 
	 * 	 * @param output
	 *            Output directory
	 */
	private static void createAndStartConsumers(File output) {
		for (int i = 0; i < NUMBER_OF_ANALYZERS; i++) {
			Thread consumerThread = new Thread(new APKAnalyzer(unpackedAPKs, output, permissionMap, suspCallTemplate),
					"Analyzer-" + i);
			allThreadCollection.add(consumerThread);
			consumerThread.start();
		}
	}

	/**
	 * Called from APKAnalyzer, if there is more to analyze 
	 * 
     * @return If there is more to analyze
	 */
	public static boolean isUnpackedProducerAlive() {
		for (Thread t : unpackedProducerThreadCollection) {
			if (t.isAlive())
				return true;
		}
		return false;
	}
	/**
	 * Called from UnpackedProducer, if there is more to unpack 
	 * 
     * @return If there is more to unpack
	 */
	public static boolean isPackedProducerAlive() {
		for (Thread t : packedProducerCollection) {
			if (t.isAlive())
				return true;
		}
		return false;
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
				callMatcher = CALLPATTERN.matcher(lineFromFile);
				callMatcher.find();
				String javaClass = callMatcher.group(1).replace(".", "/"); // to match the format in the decompiled code
				String javaMethod = callMatcher.group(2);
				call = javaClass + ";->" + javaMethod; // to match the format in the decompiled code
			}
			if (!permission.equals("") && !call.equals("")) {
				if (permissionMap.containsKey(call)) { // if a call requires more permissions, link them together with
														// "-"
					String previousPermission = permissionMap.get(call);
					if (!previousPermission.contains(permission)) {
						permissionMap.remove(call);
						permissionMap.put(call, previousPermission + "-" + permission);
					}
				} else {
					permissionMap.put(call, permission);
				}

			}
		}
		scannerMappings.close();
		return permissionMap;
	}

}
